<#
.SYNOPSIS
    Conditional Access Audit Script
.DESCRIPTION
    Connects to Microsoft Graph API and exports Conditional Access policies for compliance evidence.
.AUTHOR
    Suresh Chand
#>

# Connect to Microsoft Graph
Connect-MgGraph -Scopes "Policy.Read.All"

# Get Conditional Access Policies
$policies = Get-MgConditionalAccessPolicy

# Export to CSV
$exportPath = ".\ConditionalAccess_Audit.csv"
$policies | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime |
    Export-Csv -Path $exportPath -NoTypeInformation

Write-Output "✅ Conditional Access policies exported to $exportPath"
