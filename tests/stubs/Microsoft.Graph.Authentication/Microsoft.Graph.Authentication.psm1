# TEST STUB with the name of the Microsoft.Graph.Authentication module. Records calls and
# connects to nothing.
Import-Module (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'StubRecorder') 'StubRecorder.psd1')

function Connect-MgGraph {
    [CmdletBinding()]
    param ([string[]]$Scopes, [string]$TenantId, [switch]$NoWelcome)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function Disconnect-MgGraph {
    [CmdletBinding()]
    param ()
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

Export-ModuleMember -Function Connect-MgGraph, Disconnect-MgGraph
