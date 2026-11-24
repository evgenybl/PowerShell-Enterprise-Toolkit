# TEST STUB with the name of the ActiveDirectory module. It records every call and returns
# synthetic data from tests/data. It never contacts a domain controller.
Import-Module (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'StubRecorder') 'StubRecorder.psd1')

function Get-ADUser {
    [CmdletBinding(DefaultParameterSetName = 'Filter')]
    param (
        [Parameter(ParameterSetName = 'Identity', Mandatory, Position = 0)]$Identity,
        [Parameter(ParameterSetName = 'Filter', Mandatory)]$Filter,
        [string[]]$Properties
    )
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    $users = @(Get-StubData 'ADUsers')
    if ($PSCmdlet.ParameterSetName -eq 'Identity') {
        $match = @($users | Where-Object { Test-StubIdentity $_ $Identity })
        if ($match.Count -eq 0) {
            $err = [System.Management.Automation.ErrorRecord]::new(
                [System.Management.Automation.ItemNotFoundException]::new("Cannot find an object with identity: '$Identity'."),
                'StubADIdentityNotFound', [System.Management.Automation.ErrorCategory]::ObjectNotFound, $Identity)
            $PSCmdlet.ThrowTerminatingError($err)
        }
        return $match[0]
    }
    Select-StubByFilter -Filter $Filter -Objects $users -CallerState $PSCmdlet.SessionState
}

function Get-ADGroupMember {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)]$Identity, [switch]$Recursive)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    Get-StubMapEntry -Map (Get-StubData 'ADGroupMembers') -Key ([string]$Identity)
}

function Get-ADPrincipalGroupMembership {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)]$Identity)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    Get-StubMapEntry -Map (Get-StubData 'ADPrincipalGroups') -Key ([string]$Identity)
}

function Get-ADDomain {
    [CmdletBinding()]
    param ()
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    Get-StubData 'ADDomain'
}

function Disable-ADAccount {
    [CmdletBinding(SupportsShouldProcess)]
    param ([Parameter(Mandatory, Position = 0)]$Identity)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function Move-ADObject {
    [CmdletBinding(SupportsShouldProcess)]
    param ([Parameter(Mandatory, Position = 0)]$Identity, [Parameter(Mandatory)][string]$TargetPath)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function Set-ADAccountPassword {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, Position = 0)]$Identity,
        [securestring]$NewPassword,
        [securestring]$OldPassword,
        [switch]$Reset
    )
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function Remove-ADPrincipalGroupMembership {
    [CmdletBinding(SupportsShouldProcess)]
    param ([Parameter(Mandatory, Position = 0)]$Identity, [Parameter(Mandatory)]$MemberOf)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function Set-ADUser {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, Position = 0)]$Identity,
        $Manager,
        [AllowEmptyString()][string]$Title,
        [AllowEmptyString()][string]$Department
    )
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function New-ADUser {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, Position = 0)][string]$Name,
        [string]$GivenName,
        [string]$Surname,
        [string]$SamAccountName,
        [string]$UserPrincipalName,
        [string]$EmailAddress,
        [string]$Department,
        [string]$Title,
        [string]$Path,
        [securestring]$AccountPassword,
        [bool]$Enabled,
        [bool]$ChangePasswordAtLogon,
        $Manager
    )
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function Add-ADGroupMember {
    [CmdletBinding(SupportsShouldProcess)]
    param ([Parameter(Mandatory, Position = 0)]$Identity, [Parameter(Mandatory, Position = 1)]$Members)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function Remove-ADUser {
    # Present only so that a call would be recorded here instead of reaching a real module.
    [CmdletBinding(SupportsShouldProcess)]
    param ([Parameter(Mandatory, Position = 0)]$Identity)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

Export-ModuleMember -Function Get-ADUser, Get-ADGroupMember, Get-ADPrincipalGroupMembership, Get-ADDomain,
    Disable-ADAccount, Move-ADObject, Set-ADAccountPassword, Remove-ADPrincipalGroupMembership,
    Set-ADUser, New-ADUser, Add-ADGroupMember, Remove-ADUser
