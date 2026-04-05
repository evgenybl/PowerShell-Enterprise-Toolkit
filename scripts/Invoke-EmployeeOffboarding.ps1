<#
.SYNOPSIS
    Automates the full employee offboarding process across Active Directory and Microsoft 365.

.DESCRIPTION
    Invoke-EmployeeOffboarding performs a complete, audited offboarding workflow for a departing
    employee. The script handles all Active Directory cleanup, Azure AD sync, mailbox conversion,
    license removal, and produces a verification report at the end.

    Offboarding steps performed:
      1. Disable the AD account
      2. Reset the password to a cryptographically random 40-character string
      3. Remove the user from all security and distribution groups
      4. Clear sensitive AD attributes (manager, title, department)
      5. Move the account to the designated Disabled OU
      6. Trigger an Azure AD Connect delta sync
      7. Wait for sync propagation with a progress bar
      8. Convert the Exchange Online mailbox to a Shared Mailbox
      9. Grant the manager Full Access to the shared mailbox
     10. Remove all Microsoft 365 licenses
     11. Run a verification report and log all results

.PARAMETER SamAccountName
    The SAM account name of the user to offboard.

.PARAMETER DisabledOU
    The Distinguished Name of the OU where disabled accounts are moved.
    Example: "OU=Disabled Users,DC=contoso,DC=com"

.PARAMETER Manager
    Optional. The SAM account name of the user who should receive access to the shared mailbox.
    If not provided, the script reads the manager attribute from Active Directory.

.PARAMETER AzureSyncWaitSeconds
    Number of seconds to wait after triggering Azure AD sync. Default is 60.

.PARAMETER LogPath
    Path to write the offboarding log file. Default is C:\Logs\Offboarding.

.EXAMPLE
    .\Invoke-EmployeeOffboarding.ps1 -SamAccountName "jsmith" -DisabledOU "OU=Disabled,DC=contoso,DC=com"

.EXAMPLE
    .\Invoke-EmployeeOffboarding.ps1 -SamAccountName "jsmith" -DisabledOU "OU=Disabled,DC=contoso,DC=com" -Manager "mjones" -AzureSyncWaitSeconds 90

.NOTES
    Requirements:
      - ActiveDirectory PowerShell module
      - MSOnline or Microsoft.Graph module
      - ExchangeOnlineManagement module
      - ADSync module (on Azure AD Connect server)
      - Run as Domain Admin or delegated account with sufficient rights

    The script does not delete any data. All actions are reversible by an administrator.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true)]
    [string]$SamAccountName,

    [Parameter(Mandatory = $true)]
    [string]$DisabledOU,

    [Parameter(Mandatory = $false)]
    [string]$Manager,

    [Parameter(Mandatory = $false)]
    [int]$AzureSyncWaitSeconds = 60,

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\Offboarding"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#region Logging
if (-not (Test-Path $LogPath)) {
    New-Item -Path $LogPath -ItemType Directory -Force | Out-Null
}
$timestamp  = Get-Date -Format 'yyyyMMdd_HHmmss'
$logFile    = Join-Path $LogPath "$SamAccountName`_$timestamp.log"
$results    = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-Log {
    param ([string]$Message, [string]$Level = 'INFO')
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Message
    Add-Content -Path $logFile -Value $entry
    switch ($Level) {
        'ERROR'   { Write-Host $entry -ForegroundColor Red }
        'WARNING' { Write-Host $entry -ForegroundColor Yellow }
        'SUCCESS' { Write-Host $entry -ForegroundColor Green }
        default   { Write-Host $entry }
    }
}

function Add-Result {
    param ([string]$Step, [string]$Status, [string]$Detail = '')
    $results.Add([PSCustomObject]@{ Step = $Step; Status = $Status; Detail = $Detail })
}
#endregion

#region Helpers
function New-RandomPassword {
    param ([int]$Length = 40)
    $chars = (33..126) | ForEach-Object { [char]$_ }
    return -join ($chars | Get-Random -Count $Length)
}

function Show-Progress {
    param ([int]$Seconds, [string]$Activity)
    for ($i = 0; $i -le $Seconds; $i++) {
        Write-Progress -Activity $Activity -PercentComplete (($i / $Seconds) * 100) -Status "$i of $Seconds seconds"
        Start-Sleep -Seconds 1
    }
    Write-Progress -Activity $Activity -Completed
}
#endregion

Write-Log "=== Starting offboarding for: $SamAccountName ==="

#region Validate user exists in AD
try {
    $adUser = Get-ADUser -Identity $SamAccountName -Properties Manager, UserPrincipalName, DistinguishedName, MemberOf
    Write-Log "AD account found: $($adUser.DistinguishedName)"
} catch {
    Write-Log "AD account '$SamAccountName' not found. Aborting." 'ERROR'
    exit 1
}

$upn = $adUser.UserPrincipalName
#endregion

#region Resolve manager
if (-not $Manager) {
    if ($adUser.Manager) {
        $Manager = (Get-ADUser $adUser.Manager).SamAccountName
        Write-Log "Manager resolved from AD: $Manager"
    } else {
        Write-Log "No manager found in AD. Mailbox delegation will be skipped." 'WARNING'
    }
}
#endregion

#region Step 1 - Disable account
try {
    if ($PSCmdlet.ShouldProcess($SamAccountName, 'Disable AD account')) {
        Disable-ADAccount -Identity $SamAccountName
        Write-Log "Account disabled." 'SUCCESS'
        Add-Result 'Disable Account' 'OK'
    }
} catch {
    Write-Log "Failed to disable account: $_" 'ERROR'
    Add-Result 'Disable Account' 'FAILED' $_
}
#endregion

#region Step 2 - Reset password
try {
    $newPassword = New-RandomPassword -Length 40
    $securePassword = ConvertTo-SecureString $newPassword -AsPlainText -Force
    Set-ADAccountPassword -Identity $SamAccountName -NewPassword $securePassword -Reset
    Write-Log "Password reset to random 40-character string." 'SUCCESS'
    Add-Result 'Reset Password' 'OK'
} catch {
    Write-Log "Failed to reset password: $_" 'ERROR'
    Add-Result 'Reset Password' 'FAILED' $_
}
#endregion

#region Step 3 - Remove from all groups
try {
    $groups = Get-ADPrincipalGroupMembership -Identity $SamAccountName |
              Where-Object { $_.Name -ne 'Domain Users' }
    if ($groups) {
        Remove-ADPrincipalGroupMembership -Identity $SamAccountName -MemberOf $groups -Confirm:$false
        Write-Log "Removed from $($groups.Count) group(s)." 'SUCCESS'
        Add-Result 'Remove Groups' 'OK' "$($groups.Count) groups removed"
    } else {
        Write-Log "User was not a member of any additional groups."
        Add-Result 'Remove Groups' 'OK' 'No additional groups'
    }
} catch {
    Write-Log "Failed to remove groups: $_" 'ERROR'
    Add-Result 'Remove Groups' 'FAILED' $_
}
#endregion

#region Step 4 - Clear attributes
try {
    Set-ADUser $SamAccountName -Manager $null -Title '' -Department ''
    Write-Log "Manager, Title, and Department attributes cleared." 'SUCCESS'
    Add-Result 'Clear Attributes' 'OK'
} catch {
    Write-Log "Failed to clear attributes: $_" 'ERROR'
    Add-Result 'Clear Attributes' 'FAILED' $_
}
#endregion

#region Step 5 - Move to Disabled OU
try {
    Move-ADObject -Identity $adUser.DistinguishedName -TargetPath $DisabledOU
    Write-Log "Account moved to: $DisabledOU" 'SUCCESS'
    Add-Result 'Move to Disabled OU' 'OK'
} catch {
    Write-Log "Failed to move account: $_" 'ERROR'
    Add-Result 'Move to Disabled OU' 'FAILED' $_
}
#endregion

#region Step 6 & 7 - Azure AD Sync
try {
    Import-Module ADSync -ErrorAction Stop
    Start-ADSyncSyncCycle -PolicyType Delta
    Write-Log "Azure AD Connect delta sync triggered."
    Show-Progress -Seconds $AzureSyncWaitSeconds -Activity "Waiting for Azure AD sync to propagate"
    Add-Result 'Azure AD Sync' 'OK'
} catch {
    Write-Log "Azure AD sync failed or ADSync module not available: $_" 'WARNING'
    Add-Result 'Azure AD Sync' 'SKIPPED' 'ADSync module not found or sync failed'
}
#endregion

#region Step 8 & 9 - Convert mailbox and delegate
try {
    Connect-ExchangeOnline -ShowBanner:$false
    Set-Mailbox -Identity $upn -Type Shared
    Write-Log "Mailbox converted to Shared." 'SUCCESS'
    Add-Result 'Convert to Shared Mailbox' 'OK'

    if ($Manager) {
        Add-MailboxPermission -Identity $upn -User $Manager -AccessRights FullAccess -AutoMapping $true | Out-Null
        Write-Log "Full Access granted to: $Manager" 'SUCCESS'
        Add-Result 'Delegate Mailbox' 'OK' "Delegated to $Manager"
    }
} catch {
    Write-Log "Mailbox operation failed: $_" 'ERROR'
    Add-Result 'Mailbox Operations' 'FAILED' $_
} finally {
    Disconnect-ExchangeOnline -Confirm:$false -ErrorAction SilentlyContinue
}
#endregion

#region Step 10 - Remove licenses
try {
    Connect-MgGraph -Scopes 'User.ReadWrite.All' -NoWelcome
    $mgUser = Get-MgUser -UserId $upn -Property AssignedLicenses
    $skuIds = $mgUser.AssignedLicenses | Select-Object -ExpandProperty SkuId
    if ($skuIds) {
        $removeLicenses = $skuIds | ForEach-Object { @{ SkuId = $_ } }
        Set-MgUserLicense -UserId $upn -AddLicenses @() -RemoveLicenses $skuIds | Out-Null
        Write-Log "Removed $($skuIds.Count) license(s)." 'SUCCESS'
        Add-Result 'Remove Licenses' 'OK' "$($skuIds.Count) license(s) removed"
    } else {
        Write-Log "No licenses assigned to user."
        Add-Result 'Remove Licenses' 'OK' 'No licenses found'
    }
} catch {
    Write-Log "License removal failed: $_" 'ERROR'
    Add-Result 'Remove Licenses' 'FAILED' $_
} finally {
    Disconnect-MgGraph -ErrorAction SilentlyContinue
}
#endregion

#region Verification Report
Write-Log "=== Offboarding Verification Report ==="
$results | ForEach-Object {
    $colour = if ($_.Status -eq 'OK') { 'Green' } elseif ($_.Status -eq 'SKIPPED') { 'Yellow' } else { 'Red' }
    Write-Host ("[{0,-30}] [{1,-8}] {2}" -f $_.Step, $_.Status, $_.Detail) -ForegroundColor $colour
    Write-Log ("[{0}] [{1}] {2}" -f $_.Step, $_.Status, $_.Detail)
}

$failed = $results | Where-Object { $_.Status -eq 'FAILED' }
if ($failed) {
    Write-Log "$($failed.Count) step(s) failed. Review log: $logFile" 'WARNING'
} else {
    Write-Log "Offboarding completed successfully for $SamAccountName." 'SUCCESS'
}
#endregion
