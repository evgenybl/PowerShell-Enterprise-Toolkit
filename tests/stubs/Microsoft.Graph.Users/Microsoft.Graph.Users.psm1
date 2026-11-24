# TEST STUB with the name of the Microsoft.Graph.Users module. Records calls and returns
# synthetic data from tests/data. It never calls Microsoft Graph.
Import-Module (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'StubRecorder') 'StubRecorder.psd1')

function Get-MgUser {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)][string]$UserId,
        [string]$Filter,
        [switch]$All,
        [string[]]$Property,
        [string[]]$ExpandProperty
    )
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    $users = @(Get-StubData 'MgUsers')
    if ($UserId) {
        $match = $users | Where-Object { Test-StubIdentity $_ $UserId } | Select-Object -First 1
        if ($match) { return $match }
        Write-Error "Resource '$UserId' does not exist."
        return
    }
    if ($Filter) {
        # Only the simple form "property eq 'value'" is used by the scripts
        if ($Filter -notmatch "^\s*(\w+)\s+eq\s+'([^']*)'\s*$") { throw "Stub Get-MgUser: unsupported filter '$Filter'." }
        $prop = $Matches[1]; $value = $Matches[2]
        $users = @($users | Where-Object { $_.PSObject.Properties[$prop] -and $_.$prop -eq $value })
    }
    $users
}

function Get-MgUserMemberOf {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)][string]$UserId, [switch]$All)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    Get-StubMapEntry -Map (Get-StubData 'MgMemberOf') -Key $UserId
}

function Remove-MgUser {
    # Present only so that a call would be recorded here instead of reaching a real module.
    [CmdletBinding(SupportsShouldProcess)]
    param ([Parameter(Mandatory, Position = 0)][string]$UserId)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

Export-ModuleMember -Function Get-MgUser, Get-MgUserMemberOf, Remove-MgUser
