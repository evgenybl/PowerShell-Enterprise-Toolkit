<#
.SYNOPSIS
    Bulk-exports Active Directory user attributes for a list of EmployeeIDs.

.DESCRIPTION
    Export-ADUserAttributes reads a list of EmployeeIDs from a CSV or text file,
    looks up each user in Active Directory, and exports a comprehensive attribute set
    to a CSV report. Users not found in AD are logged separately.

    Useful for HR reconciliation, onboarding audits, license reviews, and compliance
    reporting where the source of truth is an HR system EmployeeID rather than a
    username or email address.

.PARAMETER InputFilePath
    Path to the input file containing EmployeeIDs. Accepts CSV (with header 'EmployeeID')
    or plain text (one EmployeeID per line).

.PARAMETER OutputFilePath
    Path for the exported CSV report. Default is C:\Reports\ADUserAttributes.csv.

.PARAMETER Properties
    Array of AD properties to export. A default set is used if not specified.

.PARAMETER IncludeDisabled
    Switch. When specified, disabled accounts are included in the output.

.EXAMPLE
    .\Export-ADUserAttributes.ps1 -InputFilePath "C:\HR\employees.csv" -OutputFilePath "C:\Reports\audit.csv"

.EXAMPLE
    .\Export-ADUserAttributes.ps1 -InputFilePath "C:\HR\ids.txt" -IncludeDisabled

.NOTES
    Requirements:
      - ActiveDirectory PowerShell module
      - Read access to AD user objects
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$InputFilePath,

    [Parameter(Mandatory = $false)]
    [string]$OutputFilePath = "C:\Reports\ADUserAttributes.csv",

    [Parameter(Mandatory = $false)]
    [string[]]$Properties = @(
        'SamAccountName', 'DisplayName', 'GivenName', 'Surname',
        'EmailAddress', 'UserPrincipalName', 'EmployeeID',
        'Department', 'Title', 'Manager', 'Description',
        'Office', 'TelephoneNumber', 'Mobile',
        'Enabled', 'LastLogonDate', 'PasswordNeverExpires',
        'PasswordLastSet', 'Created', 'Modified',
        'DistinguishedName', 'CanonicalName'
    ),

    [Parameter(Mandatory = $false)]
    [switch]$IncludeDisabled
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

#region Read input file
if (-not (Test-Path $InputFilePath)) {
    throw "Input file not found: $InputFilePath"
}

$extension = [System.IO.Path]::GetExtension($InputFilePath).ToLower()

if ($extension -eq '.csv') {
    $employeeIDs = Import-Csv -Path $InputFilePath | Select-Object -ExpandProperty EmployeeID
} else {
    $employeeIDs = Get-Content -Path $InputFilePath | Where-Object { $_ -match '\S' }
}

$employeeIDs = $employeeIDs | ForEach-Object { $_.Trim() } | Where-Object { $_ }
Write-Host "Loaded $($employeeIDs.Count) EmployeeIDs from: $InputFilePath" -ForegroundColor Cyan
#endregion

#region Lookup users
$found      = [System.Collections.Generic.List[PSCustomObject]]::new()
$notFound   = [System.Collections.Generic.List[string]]::new()
$counter    = 0

foreach ($id in $employeeIDs) {
    $counter++
    Write-Progress -Activity "Querying Active Directory" -Status "$counter of $($employeeIDs.Count): EmployeeID $id" -PercentComplete (($counter / $employeeIDs.Count) * 100)

    try {
        $filter = "EmployeeID -eq '$id'"
        if (-not $IncludeDisabled) {
            $filter = "EmployeeID -eq '$id' -and Enabled -eq `$true"
        }

        $user = Get-ADUser -Filter ([scriptblock]::Create($filter)) -Properties $Properties

        if ($user) {
            $managerName = ''
            if ($user.Manager) {
                try { $managerName = (Get-ADUser $user.Manager).SamAccountName } catch { }
            }

            $exportObj = [ordered]@{}
            foreach ($prop in $Properties) {
                $exportObj[$prop] = switch ($prop) {
                    'Manager'       { $managerName }
                    'LastLogonDate' { if ($user.LastLogonDate) { $user.LastLogonDate.ToString('yyyy-MM-dd HH:mm') } else { 'Never' } }
                    'PasswordLastSet' { if ($user.PasswordLastSet) { $user.PasswordLastSet.ToString('yyyy-MM-dd HH:mm') } else { '' } }
                    'Created'       { if ($user.Created) { $user.Created.ToString('yyyy-MM-dd') } else { '' } }
                    'Modified'      { if ($user.Modified) { $user.Modified.ToString('yyyy-MM-dd') } else { '' } }
                    default         { $user.$prop }
                }
            }

            $found.Add([PSCustomObject]$exportObj)
        } else {
            $notFound.Add($id)
        }
    } catch {
        Write-Warning "Error looking up EmployeeID '$id': $_"
        $notFound.Add($id)
    }
}
Write-Progress -Activity "Querying Active Directory" -Completed
#endregion

#region Export results
$outputDir = Split-Path $OutputFilePath -Parent
if (-not (Test-Path $outputDir)) { New-Item -Path $outputDir -ItemType Directory -Force | Out-Null }

$found | Export-Csv -Path $OutputFilePath -Encoding UTF8 -NoTypeInformation

if ($notFound.Count -gt 0) {
    $notFoundPath = [System.IO.Path]::ChangeExtension($OutputFilePath, '.notfound.txt')
    $notFound | Set-Content -Path $notFoundPath -Encoding UTF8
    Write-Host "Not found IDs saved to: $notFoundPath" -ForegroundColor Yellow
}

Write-Host "`nExport complete." -ForegroundColor Green
Write-Host "  Found    : $($found.Count)"    -ForegroundColor Green
Write-Host "  Not found: $($notFound.Count)" -ForegroundColor Yellow
Write-Host "  Output   : $OutputFilePath"
#endregion

return $found
