<#
.SYNOPSIS
    Generates a detailed Microsoft 365 license usage and waste report.

.DESCRIPTION
    Get-M365LicenseReport connects to Microsoft Graph and produces a full inventory of
    assigned licenses across the tenant, highlighting unused or partially-used SKUs.

    The report includes per-SKU totals, per-user assignment details, accounts with
    licenses but no recent sign-in activity, and an estimated monthly cost summary
    based on configurable per-license pricing.

.PARAMETER ExportPath
    Directory where the CSV reports are saved. Default is C:\Reports\M365Licenses.

.PARAMETER InactiveDays
    Accounts with no sign-in for this many days are flagged as candidates for
    license reclamation. Default is 90.

.PARAMETER LicensePricing
    Hashtable mapping SKU part numbers to monthly USD cost per seat.
    Used to calculate estimated waste. Optional.

.EXAMPLE
    .\Get-M365LicenseReport.ps1 -ExportPath "C:\Reports"

.EXAMPLE
    $pricing = @{ 'SPE_E3' = 36; 'ENTERPRISEPACK' = 23; 'EXCHANGE_S_STANDARD' = 4 }
    .\Get-M365LicenseReport.ps1 -InactiveDays 60 -LicensePricing $pricing

.NOTES
    Requirements:
      - Microsoft.Graph PowerShell module (Install-Module Microsoft.Graph)
      - Scopes: Organization.Read.All, User.Read.All, AuditLog.Read.All
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = "C:\Reports\M365Licenses",

    [Parameter(Mandatory = $false)]
    [int]$InactiveDays = 90,

    [Parameter(Mandatory = $false)]
    [hashtable]$LicensePricing = @{}
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if (-not (Test-Path $ExportPath)) { New-Item -Path $ExportPath -ItemType Directory -Force | Out-Null }

Connect-MgGraph -Scopes 'Organization.Read.All', 'User.Read.All', 'AuditLog.Read.All' -NoWelcome

$inactiveThreshold = (Get-Date).AddDays(-$InactiveDays)
$timestamp         = Get-Date -Format 'yyyyMMdd_HHmmss'

Write-Host "Retrieving tenant license SKUs..." -ForegroundColor Cyan

#region SKU Summary
$skus = Get-MgSubscribedSku | Select-Object SkuPartNumber, SkuId,
    @{ Name = 'Total';     Expression = { $_.PrepaidUnits.Enabled } },
    @{ Name = 'Assigned';  Expression = { $_.ConsumedUnits } },
    @{ Name = 'Available'; Expression = { $_.PrepaidUnits.Enabled - $_.ConsumedUnits } }

$skuPath = Join-Path $ExportPath "SKU_Summary_$timestamp.csv"
$skus | Export-Csv -Path $skuPath -Encoding UTF8 -NoTypeInformation

Write-Host "SKU summary: $skuPath" -ForegroundColor Green
Write-Host ("{0,-40} {1,8} {2,10} {3,10}" -f 'SKU', 'Total', 'Assigned', 'Available')
$skus | ForEach-Object {
    $colour = if ($_.Available -lt 5) { 'Yellow' } else { 'White' }
    Write-Host ("{0,-40} {1,8} {2,10} {3,10}" -f $_.SkuPartNumber, $_.Total, $_.Assigned, $_.Available) -ForegroundColor $colour
}
#endregion

#region Per-user license details
Write-Host "`nRetrieving user license assignments..." -ForegroundColor Cyan

$users = Get-MgUser -All -Property Id, DisplayName, UserPrincipalName, AssignedLicenses,
                                   SignInActivity, AccountEnabled, Department, JobTitle |
    Where-Object { $_.AssignedLicenses.Count -gt 0 }

$skuMap = @{}
Get-MgSubscribedSku | ForEach-Object { $skuMap[$_.SkuId] = $_.SkuPartNumber }

$userReport  = [System.Collections.Generic.List[PSCustomObject]]::new()
$wasteReport = [System.Collections.Generic.List[PSCustomObject]]::new()

foreach ($user in $users) {
    $lastSignIn  = $user.SignInActivity.LastSignInDateTime
    $isInactive  = $lastSignIn -and $lastSignIn -lt $inactiveThreshold
    $skuNames    = $user.AssignedLicenses | ForEach-Object { $skuMap[$_.SkuId] } | Where-Object { $_ }
    $estimatedCost = ($skuNames | ForEach-Object { if ($LicensePricing[$_]) { $LicensePricing[$_] } else { 0 } } | Measure-Object -Sum).Sum

    $entry = [PSCustomObject]@{
        DisplayName       = $user.DisplayName
        UserPrincipalName = $user.UserPrincipalName
        Department        = $user.Department
        JobTitle          = $user.JobTitle
        AccountEnabled    = $user.AccountEnabled
        Licenses          = $skuNames -join '; '
        LicenseCount      = $skuNames.Count
        LastSignIn        = if ($lastSignIn) { $lastSignIn.ToString('yyyy-MM-dd') } else { 'Never' }
        InactiveDays      = if ($lastSignIn) { [int]((Get-Date) - $lastSignIn).TotalDays } else { 9999 }
        IsInactive        = $isInactive -or (-not $lastSignIn)
        EstimatedCost_USD = $estimatedCost
    }

    $userReport.Add($entry)
    if ($entry.IsInactive) { $wasteReport.Add($entry) }
}

$userPath  = Join-Path $ExportPath "User_Licenses_$timestamp.csv"
$wastePath = Join-Path $ExportPath "Inactive_Licensed_Users_$timestamp.csv"

$userReport  | Export-Csv -Path $userPath  -Encoding UTF8 -NoTypeInformation
$wasteReport | Export-Csv -Path $wastePath -Encoding UTF8 -NoTypeInformation
#endregion

#region Summary
$totalWasteCost = ($wasteReport | Measure-Object -Property EstimatedCost_USD -Sum).Sum

Write-Host "`n=== License Report Summary ===" -ForegroundColor Cyan
Write-Host "Total licensed users   : $($userReport.Count)"
Write-Host "Inactive licensed users: $($wasteReport.Count)" -ForegroundColor Yellow

if ($totalWasteCost -gt 0) {
    Write-Host "Estimated monthly waste: `$$([Math]::Round($totalWasteCost, 2)) USD" -ForegroundColor Red
}

Write-Host "`nReports saved to: $ExportPath"
#endregion

Disconnect-MgGraph
