<#
.SYNOPSIS
    Sends automated email reminders to users whose Active Directory passwords are expiring soon.

.DESCRIPTION
    Send-PasswordExpiryNotification queries Active Directory for enabled user accounts with
    expiring passwords and sends HTML-formatted reminder emails at configurable intervals.

    Default behaviour notifies users at 14 days and 2 days before expiry. Both thresholds
    are fully configurable. The script supports a test mode that simulates sending without
    delivering any email, and an optional log file for auditing all notifications sent.

.PARAMETER SMTPServer
    FQDN or IP address of the SMTP relay server.

.PARAMETER FromAddress
    The sender email address for all outgoing notifications.

.PARAMETER DaysThreshold
    Array of day intervals at which reminders are sent. Default is @(14, 2).

.PARAMETER LogPath
    Optional. Path to write a notification audit log.

.PARAMETER WhatIf
    Simulates the process without sending any emails. Reports which users would receive notifications.

.EXAMPLE
    .\Send-PasswordExpiryNotification.ps1 -SMTPServer "smtp.contoso.com" -FromAddress "noreply@contoso.com"

.EXAMPLE
    .\Send-PasswordExpiryNotification.ps1 -SMTPServer "smtp.contoso.com" -FromAddress "noreply@contoso.com" -DaysThreshold @(30, 14, 7, 1) -LogPath "C:\Logs\PasswordExpiry.log"

.EXAMPLE
    .\Send-PasswordExpiryNotification.ps1 -SMTPServer "smtp.contoso.com" -FromAddress "noreply@contoso.com" -WhatIf

.NOTES
    Requirements:
      - ActiveDirectory PowerShell module
      - Network access to the SMTP server from the machine running the script
      - Read access to AD user objects including password attributes

    Recommended schedule: Run daily via Task Scheduler or as an Azure Automation runbook.
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true)]
    [string]$SMTPServer,

    [Parameter(Mandatory = $true)]
    [string]$FromAddress,

    [Parameter(Mandatory = $false)]
    [int[]]$DaysThreshold = @(14, 2),

    [Parameter(Mandatory = $false)]
    [string]$LogPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

$today        = (Get-Date).Date
$notified     = 0
$skipped      = 0
$errors       = 0
$logEntries   = [System.Collections.Generic.List[string]]::new()

function Write-Log {
    param ([string]$Message)
    $entry = "[{0}] {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Message
    $logEntries.Add($entry)
    Write-Host $entry
}

function Get-ExpiryEmailBody {
    param (
        [string]$DisplayName,
        [string]$ExpiryDateFormatted,
        [int]$DaysRemaining,
        [string]$HelpDeskEmail,
        [string]$HelpDeskPhone
    )
    return @"
<!DOCTYPE html>
<html>
<body style="font-family: Arial, sans-serif; font-size: 14px; color: #333;">
  <p>Hello <strong>$DisplayName</strong>,</p>
  <p>This is an automated reminder from your IT department.</p>
  <p>Your network password will expire in <strong>$DaysRemaining day(s)</strong>, on <strong>$ExpiryDateFormatted</strong>.</p>
  <p>To change your password:</p>
  <ul>
    <li>Press <strong>Ctrl + Alt + Delete</strong> and select <em>Change a password</em></li>
    <li>Or contact the IT Help Desk for assistance</li>
  </ul>
  <p><strong>Password requirements:</strong></p>
  <ul>
    <li>Minimum 12 characters</li>
    <li>Must include uppercase letters (A-Z), lowercase letters (a-z), numbers (0-9), and special characters</li>
    <li>Must not match any of your previous passwords</li>
    <li>Must not contain your name or username</li>
  </ul>
  <p>If you do not update your password before <strong>$ExpiryDateFormatted</strong>, you may be locked out
     of your workstation and company systems without warning.</p>
  <p>Need help? Contact IT Support:</p>
  <ul>
    <li>Email: <a href="mailto:$HelpDeskEmail">$HelpDeskEmail</a></li>
    <li>Phone: $HelpDeskPhone</li>
  </ul>
  <p>Best regards,<br/>IT Department</p>
</body>
</html>
"@
}

#region Configuration - customise these values
$helpDeskEmail  = "helpdesk@contoso.com"
$helpDeskPhone  = "+1 (555) 000-0000"
$subjectTemplate = "Action Required: Your password expires in {0} day(s)"
#endregion

Write-Log "Password Expiry Notification | Thresholds: $($DaysThreshold -join ', ') days"

#region Query AD
$users = Get-ADUser -Filter {
    Enabled              -eq $true -and
    PasswordNeverExpires -eq $false
} -Properties DisplayName, EmailAddress, SamAccountName, 'msDS-UserPasswordExpiryTimeComputed' |
    Where-Object { $_.EmailAddress } |
    Select-Object DisplayName, EmailAddress, SamAccountName,
        @{ Name = 'ExpiryDate'; Expression = { [datetime]::FromFileTime($_.'msDS-UserPasswordExpiryTimeComputed') } }

Write-Log "Found $($users.Count) enabled users with expiring passwords."
#endregion

foreach ($user in $users) {
    $expiryDate    = $user.ExpiryDate.Date
    $daysRemaining = ($expiryDate - $today).Days

    if ($daysRemaining -notin $DaysThreshold) {
        $skipped++
        continue
    }

    $subject    = $subjectTemplate -f $daysRemaining
    $body       = Get-ExpiryEmailBody `
                    -DisplayName        $user.DisplayName `
                    -ExpiryDateFormatted $expiryDate.ToString('dddd, MMMM d, yyyy') `
                    -DaysRemaining      $daysRemaining `
                    -HelpDeskEmail      $helpDeskEmail `
                    -HelpDeskPhone      $helpDeskPhone

    if ($PSCmdlet.ShouldProcess($user.EmailAddress, "Send password expiry reminder ($daysRemaining days)")) {
        try {
            Send-MailMessage `
                -SmtpServer $SMTPServer `
                -From       $FromAddress `
                -To         $user.EmailAddress `
                -Subject    $subject `
                -Body       $body `
                -BodyAsHtml `
                -Priority   High `
                -Encoding   UTF8

            Write-Log "SENT | $($user.SamAccountName) | $($user.EmailAddress) | Expires: $($expiryDate.ToString('yyyy-MM-dd')) | Days: $daysRemaining"
            $notified++
        } catch {
            Write-Log "FAILED | $($user.SamAccountName) | Error: $_"
            $errors++
        }
    } else {
        Write-Log "WHATIF | Would notify: $($user.SamAccountName) | Expires in $daysRemaining day(s)"
        $notified++
    }
}

Write-Log "=== Summary | Notified: $notified | Skipped: $skipped | Errors: $errors ==="

if ($LogPath) {
    $logDir = Split-Path $LogPath -Parent
    if (-not (Test-Path $logDir)) { New-Item -Path $logDir -ItemType Directory -Force | Out-Null }
    $logEntries | Add-Content -Path $LogPath -Encoding UTF8
    Write-Host "Log saved to: $LogPath"
}
