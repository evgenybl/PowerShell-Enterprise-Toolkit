<#
.SYNOPSIS
    Reports on all Entra ID guest users and flags accounts that may pose a security risk.

.DESCRIPTION
    Get-EntraGuestReport retrieves all guest (B2B) user accounts from Entra ID and produces
    a risk-rated report. Guest accounts are a common security blind spot - they are invited
    for a project, forgotten, and remain active indefinitely with access to internal resources.

    Risk flags applied:
      - Guest accounts inactive for more than the threshold period
      - Guest accounts with no recorded sign-in activity
      - Guest accounts with privileged role assignments
      - Guest accounts that are members of more than a configurable number of groups
      - Guest accounts whose invitation has never been accepted

.PARAMETER ExportPath
    Path for the output CSV report. Default is C:\Reports\EntraGuests.csv.

.PARAMETER InactiveDays
    Guest accounts with no sign-in activity for this many days are flagged. Default is 90.

.PARAMETER GroupMembershipThreshold
    Guest accounts in more than this number of groups are flagged for review. Default is 5.

.EXAMPLE
    .\Get-EntraGuestReport.ps1

.EXAMPLE
    .\Get-EntraGuestReport.ps1 -InactiveDays 60 -ExportPath "C:\Audits\Guests.csv"

.NOTES
    Requirements:
      - Microsoft.Graph PowerShell module
      - Scopes: User.Read.All, AuditLog.Read.All, GroupMember.Read.All, RoleManagement.Read.Directory
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = "C:\Reports\EntraGuests.csv",

    [Parameter(Mandatory = $false)]
    [int]$InactiveDays = 90,

    [Parameter(Mandatory = $false)]
    [int]$GroupMembershipThreshold = 5
)

Set-StrictMode -Version Latest

Connect-MgGraph -Scopes 'User.Read.All', 'AuditLog.Read.All', 'GroupMember.Read.All', 'RoleManagement.Read.Directory' -NoWelcome

$inactiveThreshold = (Get-Date).AddDays(-$InactiveDays)
$report = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "Retrieving guest accounts..." -ForegroundColor Cyan
$guests = Get-MgUser -Filter "userType eq 'Guest'" -All `
    -Property Id, DisplayName, UserPrincipalName, Mail, CreatedDateTime,
              SignInActivity, ExternalUserState, Department, CompanyName

Write-Host "Found $($guests.Count) guest accounts. Analysing..." -ForegroundColor Cyan

# Get privileged role assignments once
$roleAssignments = Get-MgRoleManagementDirectoryRoleAssignment -All -ExpandProperty Principal
$privilegedUserIds = $roleAssignments | Select-Object -ExpandProperty PrincipalId | Select-Object -Unique

$counter = 0
foreach ($guest in $guests) {
    $counter++
    Write-Progress -Activity "Analysing guest accounts" -Status "$counter of $($guests.Count)" -PercentComplete (($counter / $guests.Count) * 100)

    $lastSignIn    = $guest.SignInActivity.LastSignInDateTime
    $isInactive    = -not $lastSignIn -or $lastSignIn -lt $inactiveThreshold
    $daysSinceLogin = if ($lastSignIn) { [int]((Get-Date) - $lastSignIn).TotalDays } else { 9999 }

    # Group membership count
    $groupCount = 0
    try {
        $groupCount = (Get-MgUserMemberOf -UserId $guest.Id -All).Count
    } catch { }

    $isPrivileged      = $guest.Id -in $privilegedUserIds
    $invitePending     = $guest.ExternalUserState -eq 'PendingAcceptance'
    $riskFlags         = [System.Collections.Generic.List[string]]::new()

    if ($isInactive)                               { $riskFlags.Add("Inactive >$InactiveDays days") }
    if (-not $lastSignIn)                           { $riskFlags.Add('Never signed in') }
    if ($isPrivileged)                              { $riskFlags.Add('Has privileged role') }
    if ($groupCount -gt $GroupMembershipThreshold)  { $riskFlags.Add("Member of $groupCount groups") }
    if ($invitePending)                             { $riskFlags.Add('Invitation not accepted') }

    $riskLevel = if ($isPrivileged)          { 'Critical' }
                 elseif ($riskFlags.Count -ge 3) { 'High' }
                 elseif ($riskFlags.Count -ge 2) { 'Medium' }
                 elseif ($riskFlags.Count -ge 1) { 'Low' }
                 else                             { 'None' }

    $report.Add([PSCustomObject]@{
        DisplayName       = $guest.DisplayName
        UserPrincipalName = $guest.UserPrincipalName
        Mail              = $guest.Mail
        CompanyName       = $guest.CompanyName
        Department        = $guest.Department
        Created           = if ($guest.CreatedDateTime) { $guest.CreatedDateTime.ToString('yyyy-MM-dd') } else { '' }
        LastSignIn        = if ($lastSignIn) { $lastSignIn.ToString('yyyy-MM-dd') } else { 'Never' }
        DaysSinceLogin    = $daysSinceLogin
        InviteState       = $guest.ExternalUserState
        GroupCount        = $groupCount
        IsPrivileged      = $isPrivileged
        RiskLevel         = $riskLevel
        RiskFlags         = $riskFlags -join ' | '
    })
}
Write-Progress -Activity "Analysing guest accounts" -Completed

$exportDir = Split-Path $ExportPath -Parent
if (-not (Test-Path $exportDir)) { New-Item -Path $exportDir -ItemType Directory -Force | Out-Null }
$report | Sort-Object RiskLevel, DaysSinceLogin -Descending | Export-Csv -Path $ExportPath -Encoding UTF8 -NoTypeInformation

Write-Host "`n=== Entra Guest Report Summary ===" -ForegroundColor Cyan
foreach ($level in @('Critical','High','Medium','Low','None')) {
    $count  = ($report | Where-Object { $_.RiskLevel -eq $level }).Count
    $colour = switch ($level) { 'Critical' { 'Red' } 'High' { 'Magenta' } 'Medium' { 'Yellow' } 'Low' { 'Cyan' } default { 'White' } }
    Write-Host "$level : $count guest(s)" -ForegroundColor $colour
}
Write-Host "`nTotal guests   : $($report.Count)"
Write-Host "Report saved   : $ExportPath"

Disconnect-MgGraph
