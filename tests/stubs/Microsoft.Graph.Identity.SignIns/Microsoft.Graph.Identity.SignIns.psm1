# TEST STUB with the name of the Microsoft.Graph.Identity.SignIns module.
# Records calls and returns synthetic Conditional Access policies from tests/data.
Import-Module (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'StubRecorder') 'StubRecorder.psd1')

function Get-MgIdentityConditionalAccessPolicy {
    [CmdletBinding()]
    param ([switch]$All, [string]$Filter)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    Get-StubData 'ConditionalAccessPolicies'
}

Export-ModuleMember -Function Get-MgIdentityConditionalAccessPolicy
