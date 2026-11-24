# TEST STUB with the name of the Microsoft.Graph.Identity.DirectoryManagement module.
# Records calls and returns synthetic subscribed SKUs from tests/data.
Import-Module (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'StubRecorder') 'StubRecorder.psd1')

function Get-MgSubscribedSku {
    [CmdletBinding()]
    param ([switch]$All)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    Get-StubData 'SubscribedSkus'
}

Export-ModuleMember -Function Get-MgSubscribedSku
