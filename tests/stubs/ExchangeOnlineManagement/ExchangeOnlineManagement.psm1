# TEST STUB with the name of the ExchangeOnlineManagement module. It records every call and
# returns synthetic data from tests/data. It never connects to Exchange Online.
# In the real module, Get-Mailbox, Get-MailboxPermission, Set-Mailbox and the other
# non-EXO cmdlets are loaded after Connect-ExchangeOnline; here they are plain functions.
Import-Module (Join-Path (Join-Path (Split-Path $PSScriptRoot -Parent) 'StubRecorder') 'StubRecorder.psd1')

function Find-StubMailbox {
    param ([string]$Identity)
    @(Get-StubData 'Mailboxes') | Where-Object { Test-StubIdentity $_ $Identity } | Select-Object -First 1
}

function Connect-ExchangeOnline {
    [CmdletBinding()]
    param ([switch]$ShowBanner, [string]$Organization, [string]$UserPrincipalName)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function Disconnect-ExchangeOnline {
    [CmdletBinding(SupportsShouldProcess)]
    param ()
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function Get-EXOMailbox {
    [CmdletBinding()]
    param (
        [Parameter(Position = 0)][string]$Identity,
        [string]$Filter,
        [string[]]$RecipientTypeDetails,
        $ResultSize,
        [string[]]$Properties,
        [string[]]$PropertySets
    )
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    $boxes = @(Get-StubData 'Mailboxes')
    if ($Identity) { $boxes = @($boxes | Where-Object { Test-StubIdentity $_ $Identity }) }
    if ($RecipientTypeDetails) { $boxes = @($boxes | Where-Object { $_.RecipientTypeDetails -in $RecipientTypeDetails }) }
    if ($Filter) { $boxes = @(Select-StubByFilter -Filter $Filter -Objects $boxes -CallerState $PSCmdlet.SessionState) }
    $boxes
}

function Get-EXOMailboxStatistics {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)][string]$Identity, [string[]]$PropertySets, [string[]]$Properties)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    $box = Find-StubMailbox $Identity
    if ($box -and $box.Statistics) { return $box.Statistics }
    Write-Error "The specified mailbox statistics for '$Identity' were not found."
}

function Get-Mailbox {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)][string]$Identity)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    $box = Find-StubMailbox $Identity
    if ($box) { return $box }
    Write-Error "The operation couldn't be performed because object '$Identity' couldn't be found."
}

function Get-MailboxPermission {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)][string]$Identity)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    $box = Find-StubMailbox $Identity
    if ($box) { $box.FullAccess }
}

function Get-RecipientPermission {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)][string]$Identity)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    $box = Find-StubMailbox $Identity
    if ($box) { $box.SendAs }
}

function Get-MailboxFolderPermission {
    [CmdletBinding()]
    param ([Parameter(Mandatory, Position = 0)][string]$Identity)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    $mailboxPart, $folderPart = $Identity -split ':\\', 2
    $box = Find-StubMailbox $mailboxPart
    if ($box -and $folderPart -eq 'Calendar') { return $box.CalendarPermissions }
    Write-Error "The operation couldn't be performed because '$Identity' couldn't be found."
}

function Set-Mailbox {
    [CmdletBinding(SupportsShouldProcess)]
    param ([Parameter(Mandatory, Position = 0)][string]$Identity, [string]$Type)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

function Add-MailboxPermission {
    [CmdletBinding(SupportsShouldProcess)]
    param (
        [Parameter(Mandatory, Position = 0)][string]$Identity,
        [string]$User,
        [string[]]$AccessRights,
        [bool]$AutoMapping
    )
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
    [pscustomobject]@{ Identity = $Identity; User = $User; AccessRights = $AccessRights }
}

function Remove-Mailbox {
    # Present only so that a call would be recorded here instead of reaching a real module.
    [CmdletBinding(SupportsShouldProcess)]
    param ([Parameter(Mandatory, Position = 0)][string]$Identity)
    Write-StubCall -Command $MyInvocation.MyCommand.Name -Parameters $PSBoundParameters
}

Export-ModuleMember -Function Connect-ExchangeOnline, Disconnect-ExchangeOnline, Get-EXOMailbox, Get-EXOMailboxStatistics,
    Get-Mailbox, Get-MailboxPermission, Get-RecipientPermission, Get-MailboxFolderPermission,
    Set-Mailbox, Add-MailboxPermission, Remove-Mailbox
