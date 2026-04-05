<#
.SYNOPSIS
    Generates a comprehensive mailbox permission report for Exchange Online.

.DESCRIPTION
    Get-MailboxPermissionReport exports all non-default, non-inherited mailbox permissions
    across an Exchange Online tenant. This includes Full Access, Send As, Send on Behalf,
    and Calendar delegations.

    Use cases:
      - Offboarding audits to identify who has access to a departing employee's mailbox
      - Compliance reviews of shared mailbox access
      - Security audits of over-privileged mailbox delegations
      - Documentation of shared and resource mailbox configurations

.PARAMETER MailboxType
    Filter by mailbox type. Valid values: All, UserMailbox, SharedMailbox, RoomMailbox, EquipmentMailbox.
    Default is All.

.PARAMETER ExportPath
    Path for the output CSV file. Default is C:\Reports\MailboxPermissions.csv.

.PARAMETER IncludeCalendar
    Switch. When specified, calendar folder permissions are also included.

.PARAMETER ExcludeSystemAccounts
    Switch. Excludes known system/service accounts (NT AUTHORITY, Discovery Management, etc.)
    from the permission output. Default is true.

.EXAMPLE
    .\Get-MailboxPermissionReport.ps1

.EXAMPLE
    .\Get-MailboxPermissionReport.ps1 -MailboxType SharedMailbox -IncludeCalendar -ExportPath "C:\Audits\SharedMailboxPermissions.csv"

.NOTES
    Requirements:
      - ExchangeOnlineManagement module (Install-Module ExchangeOnlineManagement)
      - Exchange Online admin role or appropriate delegated permissions
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [ValidateSet('All','UserMailbox','SharedMailbox','RoomMailbox','EquipmentMailbox')]
    [string]$MailboxType = 'All',

    [Parameter(Mandatory = $false)]
    [string]$ExportPath = "C:\Reports\MailboxPermissions.csv",

    [Parameter(Mandatory = $false)]
    [switch]$IncludeCalendar,

    [Parameter(Mandatory = $false)]
    [switch]$ExcludeSystemAccounts = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

Connect-ExchangeOnline -ShowBanner:$false

$systemPatterns = @(
    'NT AUTHORITY\\',
    'S-1-5-',
    'Discovery Management',
    'Organization Management',
    'Exchange Services',
    'Exchange Online-ApplicationAccount'
)

function IsSystemAccount {
    param ([string]$Identity)
    foreach ($pattern in $systemPatterns) {
        if ($Identity -like "*$pattern*") { return $true }
    }
    return $false
}

$permissions = [System.Collections.Generic.List[PSCustomObject]]::new()

Write-Host "Retrieving mailboxes (Type: $MailboxType)..." -ForegroundColor Cyan

$mailboxes = if ($MailboxType -eq 'All') {
    Get-EXOMailbox -ResultSize Unlimited -Properties DisplayName, UserPrincipalName, RecipientTypeDetails, PrimarySmtpAddress
} else {
    Get-EXOMailbox -RecipientTypeDetails $MailboxType -ResultSize Unlimited -Properties DisplayName, UserPrincipalName, RecipientTypeDetails, PrimarySmtpAddress
}

Write-Host "Found $($mailboxes.Count) mailbox(es). Retrieving permissions..." -ForegroundColor Cyan

$counter = 0
foreach ($mailbox in $mailboxes) {
    $counter++
    Write-Progress -Activity "Processing mailboxes" -Status "$counter of $($mailboxes.Count): $($mailbox.DisplayName)" -PercentComplete (($counter / $mailboxes.Count) * 100)

    #region Full Access
    try {
        $fullAccess = Get-MailboxPermission -Identity $mailbox.UserPrincipalName |
            Where-Object {
                $_.AccessRights -contains 'FullAccess' -and
                -not $_.IsInherited -and
                $_.User -ne 'NT AUTHORITY\SELF' -and
                (-not $ExcludeSystemAccounts -or -not (IsSystemAccount $_.User))
            }

        foreach ($perm in $fullAccess) {
            $permissions.Add([PSCustomObject]@{
                Mailbox           = $mailbox.DisplayName
                MailboxUPN        = $mailbox.UserPrincipalName
                MailboxType       = $mailbox.RecipientTypeDetails
                PermissionType    = 'FullAccess'
                Delegate          = $perm.User
                AccessRights      = $perm.AccessRights -join ', '
                IsInherited       = $perm.IsInherited
            })
        }
    } catch { Write-Verbose "Full Access error for $($mailbox.DisplayName): $_" }
    #endregion

    #region Send As
    try {
        $sendAs = Get-RecipientPermission -Identity $mailbox.UserPrincipalName |
            Where-Object {
                $_.Trustee -ne 'NT AUTHORITY\SELF' -and
                (-not $ExcludeSystemAccounts -or -not (IsSystemAccount $_.Trustee))
            }

        foreach ($perm in $sendAs) {
            $permissions.Add([PSCustomObject]@{
                Mailbox           = $mailbox.DisplayName
                MailboxUPN        = $mailbox.UserPrincipalName
                MailboxType       = $mailbox.RecipientTypeDetails
                PermissionType    = 'SendAs'
                Delegate          = $perm.Trustee
                AccessRights      = $perm.AccessRights -join ', '
                IsInherited       = $perm.IsInherited
            })
        }
    } catch { Write-Verbose "Send As error for $($mailbox.DisplayName): $_" }
    #endregion

    #region Send on Behalf
    try {
        $mailboxDetail = Get-Mailbox -Identity $mailbox.UserPrincipalName
        if ($mailboxDetail.GrantSendOnBehalfTo) {
            foreach ($delegate in $mailboxDetail.GrantSendOnBehalfTo) {
                if (-not $ExcludeSystemAccounts -or -not (IsSystemAccount $delegate)) {
                    $permissions.Add([PSCustomObject]@{
                        Mailbox           = $mailbox.DisplayName
                        MailboxUPN        = $mailbox.UserPrincipalName
                        MailboxType       = $mailbox.RecipientTypeDetails
                        PermissionType    = 'SendOnBehalf'
                        Delegate          = $delegate
                        AccessRights      = 'SendOnBehalf'
                        IsInherited       = $false
                    })
                }
            }
        }
    } catch { Write-Verbose "Send on Behalf error for $($mailbox.DisplayName): $_" }
    #endregion

    #region Calendar Permissions
    if ($IncludeCalendar) {
        try {
            $calendarPath = "$($mailbox.UserPrincipalName):\Calendar"
            $calPerms = Get-MailboxFolderPermission -Identity $calendarPath |
                Where-Object {
                    $_.User.DisplayName -notin @('Default','Anonymous') -and
                    $_.AccessRights -notcontains 'None' -and
                    (-not $ExcludeSystemAccounts -or -not (IsSystemAccount $_.User.DisplayName))
                }

            foreach ($perm in $calPerms) {
                $permissions.Add([PSCustomObject]@{
                    Mailbox           = $mailbox.DisplayName
                    MailboxUPN        = $mailbox.UserPrincipalName
                    MailboxType       = $mailbox.RecipientTypeDetails
                    PermissionType    = 'CalendarFolder'
                    Delegate          = $perm.User.DisplayName
                    AccessRights      = $perm.AccessRights -join ', '
                    IsInherited       = $false
                })
            }
        } catch { Write-Verbose "Calendar error for $($mailbox.DisplayName): $_" }
    }
    #endregion
}

Write-Progress -Activity "Processing mailboxes" -Completed

$exportDir = Split-Path $ExportPath -Parent
if (-not (Test-Path $exportDir)) { New-Item -Path $exportDir -ItemType Directory -Force | Out-Null }
$permissions | Export-Csv -Path $ExportPath -Encoding UTF8 -NoTypeInformation

Write-Host "`n=== Mailbox Permission Report Summary ===" -ForegroundColor Cyan
Write-Host "Mailboxes processed : $($mailboxes.Count)"
Write-Host "Permission entries  : $($permissions.Count)"

$typeBreakdown = $permissions | Group-Object PermissionType | Sort-Object Count -Descending
foreach ($type in $typeBreakdown) {
    Write-Host "  $($type.Name.PadRight(20)): $($type.Count)"
}

Write-Host "`nReport saved: $ExportPath"

Disconnect-ExchangeOnline -Confirm:$false
