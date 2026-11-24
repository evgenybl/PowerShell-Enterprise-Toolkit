# TEST STUB with the name of the Microsoft.Graph.Identity.Governance module.
# Records calls and returns synthetic directory role assignments from tests/data.
Import-Module (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'StubRecorder') 'StubRecorder.psd1')

function Get-MgRoleManagementDirectoryRoleAssignment {
    [CmdletBinding()]
    param ([switch]$All, [string[]]$ExpandProperty, [string]$Filter)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    Get-StubData 'RoleAssignments'
}

Export-ModuleMember -Function Get-MgRoleManagementDirectoryRoleAssignment
