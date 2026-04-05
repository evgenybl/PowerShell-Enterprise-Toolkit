<#
.SYNOPSIS
    Automates new employee onboarding across Active Directory and Microsoft 365.

.DESCRIPTION
    Set-BulkUserOnboarding reads a CSV file of new employees and provisions each account
    end-to-end: creates the AD user, assigns it to the correct OU and groups, triggers
    an Azure AD sync, assigns Microsoft 365 licenses, and sends a welcome email with
    temporary credentials.

    The script is designed for batch processing during high-volume onboarding periods
    (new hire cohorts, acquisitions, org changes) and supports a WhatIf mode for
    review before any changes are made.

    Onboarding steps per user:
      1. Validate input data
      2. Generate a secure temporary password
      3. Create the AD user account with all standard attributes
      4. Add the user to the specified security and distribution groups
      5. Trigger Azure AD Connect sync
      6. Assign Microsoft 365 license via Microsoft Graph
      7. Send welcome email with login instructions

.PARAMETER CsvPath
    Path to the CSV file containing new employee data.
    Required columns: FirstName, LastName, Department, JobTitle, Manager, OU, License, Email

.PARAMETER SMTPServer
    FQDN of the SMTP server for sending welcome emails.

.PARAMETER FromAddress
    Sender address for welcome emails.

.PARAMETER DefaultGroups
    Array of AD group names to add every new user to. Optional.

.PARAMETER LogPath
    Directory for onboarding log files. Default is C:\Logs\Onboarding.

.EXAMPLE
    .\Set-BulkUserOnboarding.ps1 -CsvPath "C:\HR\NewHires_April2026.csv" -SMTPServer "smtp.contoso.com" -FromAddress "it@contoso.com"

.EXAMPLE
    .\Set-BulkUserOnboarding.ps1 -CsvPath "C:\HR\NewHires.csv" -SMTPServer "smtp.contoso.com" -FromAddress "it@contoso.com" -WhatIf

.NOTES
    CSV format example:
    FirstName,LastName,Department,JobTitle,Manager,OU,License,Email,Groups
    Jane,Smith,Finance,Analyst,jdoe,"OU=Finance,DC=contoso,DC=com",ENTERPRISEPACK,jane.smith@contoso.com,"Finance_DL;VPN_Access"
#>

[CmdletBinding(SupportsShouldProcess)]
param (
    [Parameter(Mandatory = $true)]
    [string]$CsvPath,

    [Parameter(Mandatory = $true)]
    [string]$SMTPServer,

    [Parameter(Mandatory = $true)]
    [string]$FromAddress,

    [Parameter(Mandatory = $false)]
    [string[]]$DefaultGroups = @(),

    [Parameter(Mandatory = $false)]
    [string]$LogPath = "C:\Logs\Onboarding"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

if (-not (Test-Path $LogPath)) { New-Item -Path $LogPath -ItemType Directory -Force | Out-Null }
$timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
$logFile   = Join-Path $LogPath "Onboarding_$timestamp.log"
$results   = [System.Collections.Generic.List[PSCustomObject]]::new()

function Write-Log {
    param ([string]$Msg, [string]$Level = 'INFO')
    $entry = "[{0}] [{1}] {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Msg
    Add-Content -Path $logFile -Value $entry
    $colour = switch ($Level) { 'ERROR' { 'Red' } 'WARNING' { 'Yellow' } 'SUCCESS' { 'Green' } default { 'White' } }
    Write-Host $entry -ForegroundColor $colour
}

function New-TemporaryPassword {
    $upper   = [char[]]('ABCDEFGHJKLMNPQRSTUVWXYZ') | Get-Random -Count 3
    $lower   = [char[]]('abcdefghjkmnpqrstuvwxyz')  | Get-Random -Count 3
    $digits  = [char[]]('23456789')                  | Get-Random -Count 3
    $special = [char[]]('!@#$%^&*')                  | Get-Random -Count 2
    $all     = ($upper + $lower + $digits + $special) | Get-Random -Count 11
    return -join $all
}

function Get-WelcomeEmailBody {
    param ([string]$DisplayName, [string]$SamAccountName, [string]$TempPassword, [string]$HelpDeskEmail)
    return @"
<html><body style="font-family:Arial;font-size:14px;">
<p>Hello <strong>$DisplayName</strong>,</p>
<p>Welcome! Your company network account has been created.</p>
<table border="1" cellpadding="6" style="border-collapse:collapse;">
  <tr><td><strong>Username</strong></td><td>$SamAccountName</td></tr>
  <tr><td><strong>Temporary Password</strong></td><td>$TempPassword</td></tr>
</table>
<p><strong>You will be required to change your password at first login.</strong></p>
<p>If you have any questions, contact IT Support: <a href="mailto:$HelpDeskEmail">$HelpDeskEmail</a></p>
<p>Best regards,<br/>IT Department</p>
</body></html>
"@
}

if (-not (Test-Path $CsvPath)) { throw "CSV not found: $CsvPath" }
$employees = Import-Csv -Path $CsvPath

Write-Log "Onboarding session started | $($employees.Count) user(s) | WhatIf=$($WhatIfPreference)"

# Get AD domain suffix
$domainSuffix = (Get-ADDomain).DNSRoot
$skuMap       = @{}
try {
    Connect-MgGraph -Scopes 'User.ReadWrite.All', 'Organization.Read.All' -NoWelcome
    Get-MgSubscribedSku | ForEach-Object { $skuMap[$_.SkuPartNumber] = $_.SkuId }
} catch {
    Write-Log "Microsoft Graph connection failed. License assignment will be skipped: $_" 'WARNING'
}

foreach ($emp in $employees) {
    $displayName    = "$($emp.FirstName) $($emp.LastName)"
    $samAccount     = ($emp.FirstName.Substring(0,1) + $emp.LastName).ToLower() -replace '[^a-z0-9]', ''
    $upn            = "$samAccount@$domainSuffix"
    $tempPassword   = New-TemporaryPassword
    $securePassword = ConvertTo-SecureString $tempPassword -AsPlainText -Force
    $status         = 'OK'
    $stepErrors     = [System.Collections.Generic.List[string]]::new()

    Write-Log "--- Processing: $displayName ($samAccount) ---"

    # Step 1 - Ensure unique SAM
    $suffix = 1
    while (Get-ADUser -Filter "SamAccountName -eq '$samAccount'" -ErrorAction SilentlyContinue) {
        $samAccount = ($emp.FirstName.Substring(0,1) + $emp.LastName + $suffix).ToLower() -replace '[^a-z0-9]', ''
        $upn        = "$samAccount@$domainSuffix"
        $suffix++
    }

    # Step 2 - Create AD user
    $managerDN = $null
    if ($emp.Manager) {
        try { $managerDN = (Get-ADUser -Identity $emp.Manager).DistinguishedName } catch { }
    }

    $adParams = @{
        Name              = $displayName
        GivenName         = $emp.FirstName
        Surname           = $emp.LastName
        SamAccountName    = $samAccount
        UserPrincipalName = $upn
        EmailAddress      = if ($emp.Email) { $emp.Email } else { $upn }
        Department        = $emp.Department
        Title             = $emp.JobTitle
        Path              = $emp.OU
        AccountPassword   = $securePassword
        Enabled           = $true
        ChangePasswordAtLogon = $true
    }
    if ($managerDN) { $adParams['Manager'] = $managerDN }

    try {
        if ($PSCmdlet.ShouldProcess($displayName, 'Create AD user')) {
            New-ADUser @adParams
            Write-Log "AD account created: $samAccount" 'SUCCESS'
        }
    } catch {
        Write-Log "Failed to create AD account for $displayName : $_" 'ERROR'
        $stepErrors.Add("AD Create: $_")
        $status = 'PARTIAL'
    }

    # Step 3 - Add to groups
    $allGroups = $DefaultGroups.Clone()
    if ($emp.Groups) { $allGroups += $emp.Groups -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }

    foreach ($group in $allGroups) {
        try {
            if ($PSCmdlet.ShouldProcess($group, "Add $samAccount")) {
                Add-ADGroupMember -Identity $group -Members $samAccount -ErrorAction Stop
                Write-Log "Added to group: $group"
            }
        } catch {
            Write-Log "Could not add to group '$group': $_" 'WARNING'
        }
    }

    # Step 4 - Azure AD sync
    try {
        if ($PSCmdlet.ShouldProcess('Azure AD Connect', 'Trigger sync')) {
            Import-Module ADSync -ErrorAction Stop
            Start-ADSyncSyncCycle -PolicyType Delta
            Write-Log "Azure AD sync triggered."
        }
    } catch {
        Write-Log "ADSync not available: $_" 'WARNING'
    }

    # Step 5 - Assign M365 license
    if ($emp.License -and $skuMap[$emp.License]) {
        try {
            if ($PSCmdlet.ShouldProcess($upn, "Assign license $($emp.License)")) {
                Start-Sleep -Seconds 10
                Set-MgUserLicense -UserId $upn -AddLicenses @{ SkuId = $skuMap[$emp.License] } -RemoveLicenses @() | Out-Null
                Write-Log "License assigned: $($emp.License)" 'SUCCESS'
            }
        } catch {
            Write-Log "License assignment failed for $upn : $_" 'WARNING'
            $stepErrors.Add("License: $_")
        }
    }

    # Step 6 - Send welcome email
    try {
        $emailTo   = if ($emp.Email) { $emp.Email } else { $upn }
        $emailBody = Get-WelcomeEmailBody -DisplayName $displayName -SamAccountName $samAccount -TempPassword $tempPassword -HelpDeskEmail $FromAddress
        if ($PSCmdlet.ShouldProcess($emailTo, 'Send welcome email')) {
            Send-MailMessage -SmtpServer $SMTPServer -From $FromAddress -To $emailTo `
                -Subject "Welcome to the company - Your IT account details" `
                -Body $emailBody -BodyAsHtml -Encoding UTF8
            Write-Log "Welcome email sent to: $emailTo" 'SUCCESS'
        }
    } catch {
        Write-Log "Welcome email failed: $_" 'WARNING'
    }

    $results.Add([PSCustomObject]@{
        DisplayName    = $displayName
        SamAccountName = $samAccount
        UPN            = $upn
        Department     = $emp.Department
        Status         = if ($stepErrors.Count -eq 0) { 'OK' } else { 'PARTIAL' }
        Errors         = $stepErrors -join '; '
    })
}

$reportPath = Join-Path $LogPath "OnboardingReport_$timestamp.csv"
$results | Export-Csv -Path $reportPath -Encoding UTF8 -NoTypeInformation

Write-Log "=== Onboarding complete | Success: $(($results | Where-Object Status -eq 'OK').Count) | Partial: $(($results | Where-Object Status -eq 'PARTIAL').Count) ==="
Write-Log "Report: $reportPath"

try { Disconnect-MgGraph } catch { }
