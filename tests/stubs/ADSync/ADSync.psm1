# TEST STUB with the name of the ADSync module. It records the call and starts nothing.
Import-Module (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'StubRecorder') 'StubRecorder.psd1')

function Start-ADSyncSyncCycle {
    [CmdletBinding(SupportsShouldProcess)]
    param ([string]$PolicyType)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

Export-ModuleMember -Function Start-ADSyncSyncCycle
