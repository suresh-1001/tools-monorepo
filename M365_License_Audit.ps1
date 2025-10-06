# This PowerShell script connects to Microsoft Graph using the Microsoft.Graph PowerShell SDK
# and audits users for specific licensing assignments. It retrieves each user's license details,
# maps SkuPartNumber values to friendly names, filters for relevant licenses, and exports the
# results to a CSV. Ensure you have the Microsoft.Graph module installed and run this
# script with an account that has the necessary permissions (e.g., User.Read.All).

# Connect to Microsoft Graph. Use Device Code auth if no session is active.
Connect-MgGraph -Scopes "User.Read.All" -ErrorAction Stop

# Fetch all users in the tenant.  The -All switch ensures that we retrieve every user.
$allUsers = Get-MgUser -All

# Define a hash table mapping SkuPartNumber values to human‑readable names.  These
# mappings are based on Microsoft documentation for product names and service plan
# identifiers: the string IDs (SkuPartNumber) correspond to the product names.
# (e.g., EXCHANGESTANDARD corresponds to Exchange Online (Plan 1)【657760597588975†L2208-L2212】,
# EXCHANGEENTERPRISE corresponds to Exchange Online (Plan 2)【657760597588975†L2234-L2236】, etc.)
$licenseMap = @{
    "EXCHANGESTANDARD"                         = "Exchange Online (Plan 1)"        # Exchange Online Plan 1【657760597588975†L2208-L2212】
    "EXCHANGEENTERPRISE"                       = "Exchange Online (Plan 2)"        # Exchange Online Plan 2【657760597588975†L2234-L2236】
    "SPB"                                     = "Microsoft 365 Business Premium"   # M365 Business Premium【657760597588975†L3909-L3914】
    "Microsoft_365_Business_Premium_(no Teams)" = "Microsoft 365 Business Premium (no Teams)" # Business Premium without Teams【657760597588975†L4028-L4030】
    "Microsoft_Teams_Enterprise"              = "Microsoft Teams Enterprise"       # Teams Enterprise【910199496044547†L320-L331】
    "ENTERPRISEPACK"                          = "Office 365 E3"                    # Office 365 E3【43226000105663†L24-L27】
    "PROJECTPREMIUM"                          = "Planner and Project Plan 5"       # New name for Project Plan 5 (assumed)
    "BI_AZURE_P3"                             = "Power BI Premium Per User"        # Power BI Premium per user【678524597949657†L1180-L1198】
    "VISIOCLIENT"                             = "Visio Plan 2"                    # Visio Plan 2【678524597949657†L1180-L1198】
    "AAD_PREMIUM_P2"                          = "Microsoft Entra ID P2"            # Formerly Azure AD Premium P2【678524597949657†L1180-L1198】
    "Microsoft_Teams_Premium"                 = "Microsoft Teams Premium"          # Teams Premium【910199496044547†L320-L331】
    "Microsoft_Teams_Rooms_Pro"               = "Microsoft Teams Rooms Pro"        # Teams Rooms Pro【910199496044547†L320-L331】
}

# Create an array to hold audit results.
$result = @()

# Iterate through each user, fetch their license details, and map assigned license names.
foreach ($user in $allUsers) {
    try {
        # Retrieve the license details for the current user.  This provides SkuId and
        # SkuPartNumber for each assigned product.
        $licenseDetails = Get-MgUserLicenseDetail -UserId $user.Id -ErrorAction Stop

        # Build a list of friendly license names for this user by matching SkuPartNumber
        # against our licenseMap.
        $assignedNames = $licenseDetails | ForEach-Object {
            # If the SkuPartNumber exists in the hash table, return the mapped name.
            $licenseMap[$_.SkuPartNumber]
        } | Where-Object { $_ }  # Remove nulls (licenses we are not auditing)

        # If the user has at least one matching license, add them to the result set.
        if ($assignedNames.Count -gt 0) {
            $result += [PSCustomObject]@{
                DisplayName       = $user.DisplayName
                UserPrincipalName = $user.UserPrincipalName
                AssignedLicenses  = ($assignedNames -join ", ")
            }
        }
    } catch {
        # If retrieving license details fails (e.g., due to permissions), log or skip.
        Write-Warning "Could not retrieve license details for $($user.UserPrincipalName): $($_.Exception.Message)"
    }
}

# Export the results to a CSV file in the current directory.  Modify the path if needed.
$csvPath = Join-Path -Path (Get-Location) -ChildPath "LicenseAuditReport.csv"
$result | Sort-Object DisplayName | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8

Write-Host "Audit complete. Report saved to $csvPath"
