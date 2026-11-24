<#
.SYNOPSIS
    Runs one toolkit script in this process with every external module replaced by the stubs
    in tests/stubs. Test-Toolkit.ps1 starts it in a child pwsh process for each scenario.

.DESCRIPTION
    - Puts tests/stubs first in $env:PSModulePath (this process only), so Import-Module and
      command auto-loading resolve ActiveDirectory, ExchangeOnlineManagement, Microsoft.Graph.*
      and ADSync to the stubs.
    - Defines Send-MailMessage, Read-Host, Start-Sleep and the user and mailbox delete commands
      as functions that only record the call.
    - Refuses to run the script (exit code 90) if any stubbed command resolves to anything
      other than a stub.
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory)][string]$ScriptPath,
    [string]$DataPath,
    [Parameter(Mandatory)][string]$RecordPath,
    [string]$ArgumentsPath,
    [string]$ReadHostAnswer = '',
    [string]$Culture
)

$ErrorActionPreference = 'Stop'
$stubRoot = [System.IO.Path]::GetFullPath((Join-Path $PSScriptRoot 'stubs'))

$env:PSModulePath      = $stubRoot + [System.IO.Path]::PathSeparator + $env:PSModulePath
$env:TOOLKIT_STUB_DATA = $DataPath
$env:TOOLKIT_STUB_LOG  = $RecordPath
$global:ToolkitReadHostAnswer = $ReadHostAnswer

Import-Module (Join-Path (Join-Path $stubRoot 'StubRecorder') 'StubRecorder.psd1')

#region Recording replacements for commands outside the stub modules
function global:Send-MailMessage {
    [CmdletBinding()]
    param (
        [string]$SmtpServer, [string]$From, [string[]]$To, [string[]]$Cc, [string[]]$Bcc,
        [string]$Subject, [string]$Body, [switch]$BodyAsHtml, [string]$Priority, $Encoding,
        [int]$Port, [switch]$UseSsl, [pscredential]$Credential, [string[]]$Attachments
    )
    Write-StubCall -Command 'Send-MailMessage' -Parameters $PSBoundParameters
}

function global:Read-Host {
    [CmdletBinding()]
    param ([Parameter(Position = 0)]$Prompt, [switch]$AsSecureString)
    Write-StubCall -Command 'Read-Host' -Parameters $PSBoundParameters
    return $global:ToolkitReadHostAnswer
}

function global:Start-Sleep {
    [CmdletBinding()]
    param ([Parameter(Position = 0)][double]$Seconds, [int]$Milliseconds)
    Write-StubCall -Command 'Start-Sleep' -Parameters $PSBoundParameters
}

function global:Remove-ADUser      { Write-StubCall -Command 'Remove-ADUser' -Parameters @{ Arguments = [string]$args } }
function global:Remove-Mailbox     { Write-StubCall -Command 'Remove-Mailbox' -Parameters @{ Arguments = [string]$args } }
function global:Remove-MgUser      { Write-StubCall -Command 'Remove-MgUser' -Parameters @{ Arguments = [string]$args } }
function global:Remove-AzureADUser { Write-StubCall -Command 'Remove-AzureADUser' -Parameters @{ Arguments = [string]$args } }
$runnerFunctions = @('Send-MailMessage', 'Read-Host', 'Start-Sleep', 'Remove-ADUser', 'Remove-Mailbox', 'Remove-MgUser', 'Remove-AzureADUser')
#endregion

#region Safety check: nothing stubbed may resolve to a real module
$comparison = [System.StringComparison]::OrdinalIgnoreCase
foreach ($dir in Get-ChildItem -LiteralPath $stubRoot -Directory) {
    if ($dir.Name -eq 'StubRecorder') { continue }
    $module = Import-Module -Name $dir.Name -PassThru -Force -WarningAction SilentlyContinue
    if (-not $module.ModuleBase.StartsWith($stubRoot, $comparison)) {
        [Console]::Error.WriteLine("SAFETY: module $($dir.Name) resolved to $($module.ModuleBase)")
        exit 90
    }
    foreach ($name in $module.ExportedFunctions.Keys) {
        $command = Get-Command -Name $name
        $isStub = ($command.Module -and $command.Module.ModuleBase.StartsWith($stubRoot, $comparison)) -or
                  ($command.CommandType -eq 'Function' -and $name -in $runnerFunctions)
        if (-not $isStub) {
            [Console]::Error.WriteLine("SAFETY: $name resolved to $($command.Source)")
            exit 90
        }
    }
}
foreach ($name in $runnerFunctions) {
    if ((Get-Command -Name $name).CommandType -ne 'Function') {
        [Console]::Error.WriteLine("SAFETY: $name is not the recording function")
        exit 90
    }
}
#endregion

function ConvertTo-PlainArgument {
    param ($Value)
    if ($Value -is [System.Collections.IDictionary]) {
        $h = @{}
        foreach ($k in $Value.Keys) { $h[$k] = ConvertTo-PlainArgument $Value[$k] }
        return $h
    }
    if ($Value -is [System.Collections.IList]) { return ,@($Value | ForEach-Object { ConvertTo-PlainArgument $_ }) }
    return $Value
}

$scriptArgs = @{}
if ($ArgumentsPath) {
    $parsed = Get-Content -LiteralPath $ArgumentsPath -Raw | ConvertFrom-Json -AsHashtable
    if ($parsed) { foreach ($k in $parsed.Keys) { $scriptArgs[$k] = ConvertTo-PlainArgument $parsed[$k] } }
}

# Convert-RegistryToGPO uses the [Microsoft.Win32.RegistryValueKind] enum only as a type tag.
# The assembly is loaded at start-up on Windows; on other systems it is loaded here if needed.
# Nothing reads or writes a registry.
if (-not ('Microsoft.Win32.RegistryValueKind' -as [type])) {
    try { Add-Type -AssemblyName 'Microsoft.Win32.Registry' } catch { }
}

if ($Culture) {
    [System.Globalization.CultureInfo]::CurrentCulture = [System.Globalization.CultureInfo]::GetCultureInfo($Culture)
}

# The script runs with the default error preference and no enclosing try/catch, as it would
# from a console: a statement-terminating error inside it is reported and the script goes on.
# A script-terminating error ends this process with exit code 1 and the error on stderr.
$ErrorActionPreference = 'Continue'
$global:LASTEXITCODE = 0
$null = & $ScriptPath @scriptArgs
exit $global:LASTEXITCODE
