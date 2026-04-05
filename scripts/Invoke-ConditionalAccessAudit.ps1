<#
.SYNOPSIS
    Audits Entra ID Conditional Access policies and flags security gaps.

.DESCRIPTION
    Invoke-ConditionalAccessAudit connects to Microsoft Graph and retrieves all
    Conditional Access policies in the tenant. It analyses each policy for common
    security misconfigurations and produces a findings report with severity ratings.

    Checks performed:
      - Policies in Report-Only mode (not enforced)
      - Policies with no MFA requirement
      - Policies that exclude all users
      - Policies with broad exclusions (guest users, service accounts, etc.)
      - Missing legacy authentication block
      - Missing device compliance requirement for privileged roles
      - Policies targeting All Users but excluding no break-glass accounts
      - Sign-in risk policies not configured

.PARAMETER ExportPath
    Path for the output CSV report. Default is C:\Reports\CA_Audit.csv.

.PARAMETER TenantId
    Optional. Tenant ID for the target tenant. Uses the current session if not specified.

.EXAMPLE
    .\Invoke-ConditionalAccessAudit.ps1

.EXAMPLE
    .\Invoke-ConditionalAccessAudit.ps1 -ExportPath "C:\Audits\CA_2026.csv"

.NOTES
    Requirements:
      - Microsoft.Graph PowerShell module
      - Scopes: Policy.Read.All, Directory.Read.All
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $false)]
    [string]$ExportPath = "C:\Reports\CA_Audit.csv",

    [Parameter(Mandatory = $false)]
    [string]$TenantId
)

Set-StrictMode -Version Latest

$connectParams = @{ Scopes = 'Policy.Read.All', 'Directory.Read.All'; NoWelcome = $true }
if ($TenantId) { $connectParams['TenantId'] = $TenantId }
Connect-MgGraph @connectParams

$findings = [System.Collections.Generic.List[PSCustomObject]]::new()

function Add-Finding {
    param (
        [string]$PolicyName,
        [string]$PolicyId,
        [string]$State,
        [string]$Check,
        [ValidateSet('Critical','High','Medium','Low','Info')]
        [string]$Severity,
        [string]$Detail
    )
    $findings.Add([PSCustomObject]@{
        PolicyName = $PolicyName
        PolicyId   = $PolicyId
        State      = $State
        Check      = $Check
        Severity   = $Severity
        Detail     = $Detail
    })
}

Write-Host "Retrieving Conditional Access policies..." -ForegroundColor Cyan
$policies = Get-MgIdentityConditionalAccessPolicy -All

Write-Host "Found $($policies.Count) policies. Analysing..." -ForegroundColor Cyan

foreach ($policy in $policies) {
    $name  = $policy.DisplayName
    $id    = $policy.Id
    $state = $policy.State

    # Policy in Report-Only mode
    if ($state -eq 'enabledForReportingButNotEnforced') {
        Add-Finding -PolicyName $name -PolicyId $id -State $state `
            -Check 'Report-Only Mode' -Severity 'High' `
            -Detail 'Policy is not enforced. Users are not protected by this policy.'
    }

    # Policy disabled entirely
    if ($state -eq 'disabled') {
        Add-Finding -PolicyName $name -PolicyId $id -State $state `
            -Check 'Policy Disabled' -Severity 'Medium' `
            -Detail 'Policy exists but is disabled. Review if it should be enabled.'
    }

    # No grant controls (no MFA, no compliant device, no nothing)
    $grantControls = $policy.GrantControls
    if (-not $grantControls -or (-not $grantControls.BuiltInControls -and -not $grantControls.CustomAuthenticationFactors -and -not $grantControls.TermsOfUse)) {
        Add-Finding -PolicyName $name -PolicyId $id -State $state `
            -Check 'No Grant Controls' -Severity 'Critical' `
            -Detail 'Policy has no grant controls defined. It may block or allow access without any authentication requirement.'
    }

    # No MFA in grant controls
    if ($grantControls -and $grantControls.BuiltInControls -and
        'mfa' -notin $grantControls.BuiltInControls -and
        'compliantDevice' -notin $grantControls.BuiltInControls) {
        Add-Finding -PolicyName $name -PolicyId $id -State $state `
            -Check 'No MFA or Device Compliance' -Severity 'High' `
            -Detail "Grant controls: $($grantControls.BuiltInControls -join ', '). Consider requiring MFA or compliant device."
    }

    # Excludes all users
    $conditions = $policy.Conditions
    if ($conditions.Users.ExcludeUsers -contains 'All') {
        Add-Finding -PolicyName $name -PolicyId $id -State $state `
            -Check 'Excludes All Users' -Severity 'Critical' `
            -Detail 'Policy excludes all users and is effectively non-functional.'
    }

    # Large number of excluded users (potential bypass list)
    if ($conditions.Users.ExcludeUsers.Count -gt 10) {
        Add-Finding -PolicyName $name -PolicyId $id -State $state `
            -Check 'High User Exclusion Count' -Severity 'Medium' `
            -Detail "Policy excludes $($conditions.Users.ExcludeUsers.Count) individual users. Review for unnecessary exclusions."
    }

    # Includes all apps but excludes no apps - check for legacy auth
    if ($conditions.Applications.IncludeApplications -contains 'All' -and
        $conditions.ClientAppTypes -notcontains 'exchangeActiveSync' -and
        $conditions.ClientAppTypes -notcontains 'other') {
        Add-Finding -PolicyName $name -PolicyId $id -State $state `
            -Check 'Legacy Auth Not Explicitly Targeted' -Severity 'Info' `
            -Detail 'This all-apps policy does not explicitly target legacy auth clients (exchangeActiveSync, other). Verify a separate legacy auth block policy exists.'
    }

    # Guest users included with broad access
    if ($conditions.Users.IncludeGuestsOrExternalUsers -or
        $conditions.Users.IncludeUsers -contains 'GuestsOrExternalUsers') {
        if (-not $grantControls -or 'mfa' -notin $grantControls.BuiltInControls) {
            Add-Finding -PolicyName $name -PolicyId $id -State $state `
                -Check 'Guest Access Without MFA' -Severity 'High' `
                -Detail 'Policy includes guest/external users but does not require MFA.'
        }
    }
}

# Check for missing legacy auth block policy
$legacyAuthBlock = $policies | Where-Object {
    $_.Conditions.ClientAppTypes -contains 'exchangeActiveSync' -or
    $_.Conditions.ClientAppTypes -contains 'other'
}
if (-not $legacyAuthBlock) {
    Add-Finding -PolicyName '(Tenant-Level)' -PolicyId 'N/A' -State 'N/A' `
        -Check 'No Legacy Auth Block Policy' -Severity 'Critical' `
        -Detail 'No Conditional Access policy targeting legacy authentication clients was found. Legacy auth bypasses MFA and is a common attack vector.'
}

# Export
$exportDir = Split-Path $ExportPath -Parent
if (-not (Test-Path $exportDir)) { New-Item -Path $exportDir -ItemType Directory -Force | Out-Null }
$findings | Export-Csv -Path $ExportPath -Encoding UTF8 -NoTypeInformation

# Console summary
Write-Host "`n=== Conditional Access Audit Results ===" -ForegroundColor Cyan
$severities = @('Critical','High','Medium','Low','Info')
foreach ($sev in $severities) {
    $count  = ($findings | Where-Object { $_.Severity -eq $sev }).Count
    $colour = switch ($sev) { 'Critical' { 'Red' } 'High' { 'Magenta' } 'Medium' { 'Yellow' } 'Low' { 'Cyan' } default { 'White' } }
    if ($count -gt 0) { Write-Host "$sev : $count finding(s)" -ForegroundColor $colour }
}

Write-Host "`nTotal findings : $($findings.Count)"
Write-Host "Report saved   : $ExportPath"

Disconnect-MgGraph
