# TEST STUB with the name of the Microsoft.Graph.Users.Actions module. Records the call and
# changes no licence.
Import-Module (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'StubRecorder') 'StubRecorder.psd1')

function Set-MgUserLicense {
    [CmdletBinding(SupportsShouldProcess)]
    param ([Parameter(Mandatory)][string]$UserId, $AddLicenses, $RemoveLicenses)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    [pscustomobject]@{ Id = $UserId }
}

Export-ModuleMember -Function Set-MgUserLicense
