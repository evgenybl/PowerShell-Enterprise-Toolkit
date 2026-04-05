<#
.SYNOPSIS
    Identifies stale user accounts by cross-checking Active Directory and Exchange Online activity.

.DESCRIPTION
    Find-StaleAccounts detects user accounts that have been inactive for a configurable number
    of days by checking both the AD LastLogonDate attribute and the Exchange Online mailbox
    LastLogonTime. Cross-referencing both sources eliminates false positives where a user
    has not logged into Windows but is still actively using their mailbox (or vice versa).

    Output includes a CSV report and an optional automatic remediation step (disable + move).

    Detection logic:
      - Accounts with EmployeeID set (excludes service accounts)
      - Accounts with an email address (excludes infrastructure accounts)
      - AD LastLogonDate older than the threshold
      - Exchange Online mailbox last logon older than the threshold (if mailbox exists)
      - Accounts with no mailbox are flagged separately

.PARAMETER DaysInactive
    Number of days of inactivity to consider an account stale. Default is 60.

.PARAMETER ExportPath
    Path for the output CSV report. Default is C:\Reports\StaleAccounts.csv.

.PARAMETER Remediate
    Switch. If specified, stale accounts are automatically disabled and moved to the
    DisabledOU. Requires DisabledOU parameter. Always prompts for confirmation first.

.PARAMETER DisabledOU
    Required when -Remediate is used. The target OU for disabled accounts.

.PARAMETER ExcludeGroups
    Array of group names. Members of these groups are excluded from the report.

.EXAMPLE
    .\Find-StaleAccounts.ps1 -DaysInactive 60 -ExportPath "C:\Reports\Stale.csv"

.EXAMPLE
    .\Find-StaleAccounts.ps1 -DaysInactive 90 -Remediate -DisabledOU "OU=Disabled,DC=contoso,DC=com"

.NOTES
    Requirements:
      - ActiveDirectory PowerShell module
      - ExchangeOnlineManagement module
      - Read access to AD user objects
      - Exchange Online admin role for mailbox statistics
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $false)]
    [int]$DaysInactive = 60,

    [Parameter(Mandatory = $false)]
    [string]$ExportPath = "C:\Reports\StaleAccounts.csv",

    [Parameter(Mandatory = $false)]
    [switch]$Remediate,

    [Parameter(Mandatory = $false)]
    [string]$DisabledOU,

    [Parameter(Mandatory = $false)]
    [string[]]$ExcludeGroups = @()
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if ($Remediate -and -not $DisabledOU) {
    throw "-DisabledOU is required when using -Remediate."
}

$threshold  = (Get-Date).AddDays(-$DaysInactive)
$reportData = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "Stale Account Detection | Threshold: $DaysInactive days ($($threshold.ToString('yyyy-MM-dd')))" -ForegroundColor Cyan
Write-Host "Connecting to Exchange Online..." -ForegroundColor Cyan

Connect-ExchangeOnline -ShowBanner:$false

#region Build exclusion list
$excludedUsers = @()
foreach ($groupName in $ExcludeGroups) {
    try {
        $members = Get-ADGroupMember -Identity $groupName -Recursive | Select-Object -ExpandProperty SamAccountName
        $excludedUsers += $members
    } catch {
        Write-Warning "Could not resolve exclusion group '$groupName': $_"
    }
}
$excludedUsers = $excludedUsers | Select-Object -Unique
#endregion

#region Query AD
Write-Host "Querying Active Directory..." -ForegroundColor Cyan
$adUsers = Get-ADUser -Filter {
    Enabled         -eq $true   -and
    EmployeeID      -ne '$null' -and
    EmailAddress    -ne '$null' -and
    LastLogonDate   -lt $threshold
} -Properties SamAccountName, UserPrincipalName, EmailAddress, DisplayName,
              EmployeeID, LastLogonDate, Department, DistinguishedName |
    Where-Object { $_.SamAccountName -notin $excludedUsers }

Write-Host "Found $($adUsers.Count) AD accounts inactive in AD for $DaysInactive+ days." -ForegroundColor Yellow
#endregion

#region Cross-check Exchange Online
$counter = 0
foreach ($user in $adUsers) {
    $counter++
    Write-Progress -Activity "Checking Exchange Online activity" -Status "$counter of $($adUsers.Count): $($user.SamAccountName)" -PercentComplete (($counter / $adUsers.Count) * 100)

    $notes          = ''
    $exoLastLogon   = $null
    $includeInReport = $false

    $mailbox = Get-ExoMailbox -Filter "UserPrincipalName -EQ '$($user.UserPrincipalName)'" -ErrorAction SilentlyContinue

    if ($mailbox) {
        $stats = Get-ExoMailboxStatistics -Identity $user.UserPrincipalName -PropertySets All -ErrorAction SilentlyContinue
        $exoLastLogon = $stats.LastLogonTime

        if (-not $exoLastLogon -or $exoLastLogon -le $threshold) {
            $includeInReport = $true
            $notes = if (-not $exoLastLogon) { 'No EXO logon recorded' } else { 'Inactive in AD and EXO' }
        }
    } else {
        $includeInReport = $true
        $notes = 'No Exchange Online mailbox'
    }

    if ($includeInReport) {
        $reportData.Add([PSCustomObject]@{
            SamAccountName   = $user.SamAccountName
            DisplayName      = $user.DisplayName
            UserPrincipalName = $user.UserPrincipalName
            Department       = $user.Department
            EmployeeID       = $user.EmployeeID
            AD_LastLogon     = if ($user.LastLogonDate) { $user.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never' }
            EXO_LastLogon    = if ($exoLastLogon)       { $exoLastLogon.ToString('yyyy-MM-dd') }      else { 'Never/None' }
            Notes            = $notes
            DistinguishedName = $user.DistinguishedName
        })
    }
}
Write-Progress -Activity "Checking Exchange Online activity" -Completed
#endregion

Disconnect-ExchangeOnline -Confirm:$false

#region Export
$exportDir = Split-Path $ExportPath -Parent
if (-not (Test-Path $exportDir)) { New-Item -Path $exportDir -ItemType Directory -Force | Out-Null }
$reportData | Export-Csv -Path $ExportPath -Encoding UTF8 -NoTypeInformation

Write-Host "`nReport saved: $ExportPath" -ForegroundColor Green
Write-Host "Total stale accounts found: $($reportData.Count)" -ForegroundColor Yellow
#endregion

#region Optional remediation
if ($Remediate -and $reportData.Count -gt 0) {
    Write-Host "`nREMEDIATION MODE: $($reportData.Count) accounts will be disabled and moved." -ForegroundColor Red
    $confirm = Read-Host "Type CONFIRM to proceed"

    if ($confirm -eq 'CONFIRM') {
        foreach ($entry in $reportData) {
            try {
                if ($PSCmdlet.ShouldProcess($entry.SamAccountName, 'Disable and move')) {
                    Disable-ADAccount -Identity $entry.SamAccountName
                    Move-ADObject -Identity $entry.DistinguishedName -TargetPath $DisabledOU
                    Write-Host "Disabled and moved: $($entry.SamAccountName)" -ForegroundColor Green
                }
            } catch {
                Write-Warning "Failed to remediate $($entry.SamAccountName): $_"
            }
        }
    } else {
        Write-Host "Remediation cancelled." -ForegroundColor Yellow
    }
}
#endregion

return $reportData
