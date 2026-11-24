#Requires -Version 7.0
<#
.SYNOPSIS
    Tests for the PowerShell Enterprise Toolkit. No test framework; PowerShell 7 on Windows or Linux.

.DESCRIPTION
    1. Static checks on every script in scripts/.
    2. Each script run in a child pwsh process (tests/Invoke-UnderStubs.ps1) with the modules it
       uses replaced by the recording stubs in tests/stubs, against the invented data in
       tests/data. Nothing contacts Active Directory, Exchange Online, Microsoft Graph, a mail
       server or the registry. Every output path is inside a new folder under the system temp
       path, which is removed at the end.

    Prints one line per assertion and ends with "RESULT: <passed> passed, <failed> failed".
    The exit code is 0 only when nothing failed.

.PARAMETER ScriptsPath
    Folder holding the scripts to test. Default: the repository's scripts folder.

.EXAMPLE
    pwsh -NoProfile -File tests/Test-Toolkit.ps1
#>
[CmdletBinding()]
param ([string]$ScriptsPath)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$repoRoot = Split-Path -Path $PSScriptRoot -Parent
if (-not $ScriptsPath) { $ScriptsPath = Join-Path $repoRoot 'scripts' }
$ScriptsPath = (Resolve-Path -LiteralPath $ScriptsPath).ProviderPath
$dataRoot    = Join-Path $PSScriptRoot 'data'
$stubRoot    = Join-Path $PSScriptRoot 'stubs'
$runner      = Join-Path $PSScriptRoot 'Invoke-UnderStubs.ps1'
$pwshPath    = Join-Path $PSHOME $(if ($IsWindows) { 'pwsh.exe' } else { 'pwsh' })

# Stub modules first in the module path: this process and the child processes it starts only
$env:PSModulePath = $stubRoot + [System.IO.Path]::PathSeparator + $env:PSModulePath

$StateChanging = @('Disable-ADAccount', 'Move-ADObject', 'Set-ADAccountPassword', 'Remove-ADPrincipalGroupMembership',
                   'Set-ADUser', 'New-ADUser', 'Add-ADGroupMember', 'Start-ADSyncSyncCycle', 'Set-Mailbox',
                   'Add-MailboxPermission', 'Set-MgUserLicense', 'Send-MailMessage')
$DeleteCommands = @('Remove-ADUser', 'Remove-Mailbox', 'Remove-MgUser', 'Remove-AzureADUser')

#region Assertion helpers
$script:Passed = 0
$script:Failed = 0

function Assert-True {
    param ([string]$Name, [bool]$Condition, [string]$Detail = '')
    if ($Condition) {
        $script:Passed++
        Write-Host "PASS  $Name"
    } else {
        $script:Failed++
        if ($Detail) { Write-Host "FAIL  $Name  [$Detail]" } else { Write-Host "FAIL  $Name" }
    }
}

function Assert-Equal {
    param ([string]$Name, $Expected, $Actual)
    $e = (@($Expected) | ForEach-Object { [string]$_ }) -join ' | '
    $a = (@($Actual) | ForEach-Object { [string]$_ }) -join ' | '
    Assert-True $Name ($e -ceq $a) "expected '$e', got '$a'"
}
#endregion

#region Scenario helpers
function Invoke-Scenario {
    # Runs one script under the stubs in a child pwsh process and returns its exit code,
    # its recorded stub calls and its output.
    param (
        [Parameter(Mandatory)][string]$Name,
        [Parameter(Mandatory)][string]$Script,
        [string]$DataFile,
        [hashtable]$Arguments = @{},
        [string]$ReadHostAnswer,
        [string]$Culture
    )
    $dir = Join-Path $script:TempRoot $Name
    New-Item -ItemType Directory -Path $dir -Force | Out-Null
    $record   = Join-Path $dir 'calls.jsonl'
    $argsFile = Join-Path $dir 'arguments.json'
    $stdout   = Join-Path $dir 'stdout.txt'
    $stderr   = Join-Path $dir 'stderr.txt'
    [System.IO.File]::WriteAllText($record, '')
    [System.IO.File]::WriteAllText($argsFile, (ConvertTo-Json -InputObject $Arguments -Depth 6))

    $runnerArgs = @('-NoProfile', '-NonInteractive', '-File', $runner,
                    '-ScriptPath', (Join-Path $ScriptsPath $Script),
                    '-RecordPath', $record, '-ArgumentsPath', $argsFile)
    if ($DataFile)       { $runnerArgs += @('-DataPath', (Join-Path $dataRoot $DataFile)) }
    if ($ReadHostAnswer) { $runnerArgs += @('-ReadHostAnswer', $ReadHostAnswer) }
    if ($Culture)        { $runnerArgs += @('-Culture', $Culture) }

    & $pwshPath @runnerArgs 1> $stdout 2> $stderr
    $exitCode = $LASTEXITCODE

    $calls = @([System.IO.File]::ReadAllLines($record) | Where-Object { $_ } | ForEach-Object { ConvertFrom-Json -InputObject $_ })
    [pscustomobject]@{
        Name     = $Name
        Dir      = $dir
        ExitCode = $exitCode
        Calls    = $calls
        Stdout   = [System.IO.File]::ReadAllText($stdout)
        Stderr   = [System.IO.File]::ReadAllText($stderr)
    }
}

function Get-Calls {
    param ($Run, [string[]]$Command)
    @($Run.Calls | Where-Object { $_.Command -in $Command })
}

function Get-CallParameter {
    param ($Call, [string]$Name)
    $p = $Call.Parameters.PSObject.Properties[$Name]
    if ($p) { $p.Value } else { $null }
}

function Assert-RanCleanly {
    # Exit code as expected and nothing on the error stream (strict-mode errors land there)
    param ($Run, [int]$ExpectedExit = 0)
    Assert-True "$($Run.Name): exit code $ExpectedExit" ($Run.ExitCode -eq $ExpectedExit) "exit code $($Run.ExitCode)"
    $err = $Run.Stderr.Trim()
    if ($err.Length -gt 300) { $err = $err.Substring(0, 300) + '...' }
    Assert-True "$($Run.Name): no error output" ($Run.Stderr.Trim().Length -eq 0) $err
}

function Assert-NoStateChange {
    param ($Run)
    $changing = @(Get-Calls $Run $StateChanging)
    Assert-True "$($Run.Name): no state-changing call recorded" ($changing.Count -eq 0) (($changing | ForEach-Object Command) -join ', ')
}

function Assert-NoDelete {
    param ($Run)
    $deletes = @(Get-Calls $Run $DeleteCommands)
    Assert-True "$($Run.Name): no delete call recorded" ($deletes.Count -eq 0) (($deletes | ForEach-Object Command) -join ', ')
}

function Test-InFilterScriptBlock {
    # True when an AST node sits inside a script block passed to -Filter (for example the
    # Get-ADUser filter { Enabled -eq $true }): its words are filter text, never run as commands
    param ([System.Management.Automation.Language.Ast]$Node)
    for ($p = $Node.Parent; $null -ne $p; $p = $p.Parent) {
        if ($p -is [System.Management.Automation.Language.ScriptBlockExpressionAst] -and
            $p.Parent -is [System.Management.Automation.Language.CommandAst]) {
            $elements = $p.Parent.CommandElements
            $i = $elements.IndexOf($p)
            if ($i -gt 0 -and $elements[$i - 1] -is [System.Management.Automation.Language.CommandParameterAst] -and
                $elements[$i - 1].ParameterName -eq 'Filter') { return $true }
        }
    }
    return $false
}

function Get-ScriptFunctionText {
    # The source text of named functions in a script, to test them without running the script
    param ([System.Management.Automation.Language.Ast]$Ast, [string[]]$Name)
    $parts = foreach ($n in $Name) {
        $fn = $Ast.Find({ param($node) $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -eq $n }, $true)
        if (-not $fn) { throw "Function $n not found" }
        $fn.Extent.Text
    }
    $parts -join [Environment]::NewLine
}
#endregion

$tempBase = [System.IO.Path]::GetTempPath()
$script:TempRoot = Join-Path $tempBase ('toolkit-tests-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $script:TempRoot | Out-Null

try {
    #region (a) Static: every script parses
    $scriptFiles = @(Get-ChildItem -LiteralPath $ScriptsPath -Filter '*.ps1' | Sort-Object Name)
    Assert-True 'static: scripts folder holds 10 scripts' ($scriptFiles.Count -eq 10) "found $($scriptFiles.Count)"
    $asts = @{}
    foreach ($file in $scriptFiles) {
        $tokens = $null; $parseErrors = $null
        $asts[$file.BaseName] = [System.Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$parseErrors)
        Assert-True "static: $($file.Name) parses with 0 errors" ($parseErrors.Count -eq 0) (($parseErrors | ForEach-Object Message) -join '; ')
    }
    #endregion

    #region (b) Static: no script deletes a user or a mailbox
    foreach ($file in $scriptFiles) {
        $commandNames = @($asts[$file.BaseName].FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ })
        $hits = @($commandNames | Where-Object { $_ -in $DeleteCommands })
        $text = [System.IO.File]::ReadAllText($file.FullName)
        $textHits = @([regex]::Matches($text, '(?i)\b(Remove-ADUser|Remove-Mailbox|Remove-MgUser|Remove-AzureADUser)\b') | ForEach-Object Value)
        Assert-True "static: $($file.Name) contains no user or mailbox delete command" (($hits.Count + $textHits.Count) -eq 0) (($hits + $textHits) -join ', ')
    }
    #endregion

    #region (c) Static: SupportsShouldProcess matches the README's -WhatIf list
    $declared = @(foreach ($file in $scriptFiles) {
        $paramBlock = $asts[$file.BaseName].ParamBlock
        $binding = if ($paramBlock) { $paramBlock.Attributes | Where-Object { $_.TypeName.Name -eq 'CmdletBinding' } } else { $null }
        $ssp = if ($binding) {
            $binding.NamedArguments | Where-Object {
                $_.ArgumentName -eq 'SupportsShouldProcess' -and ($_.ExpressionOmitted -or $_.Argument.SafeGetValue())
            }
        }
        if ($ssp) { $file.BaseName }
    }) | Sort-Object
    $readmeLines = [System.IO.File]::ReadAllLines((Join-Path $repoRoot 'README.md'))
    $whatIfLine = @($readmeLines | Where-Object { $_.Contains('support `-WhatIf`:') })
    Assert-True 'static: README has one line listing the scripts that support -WhatIf' ($whatIfLine.Count -eq 1) "found $($whatIfLine.Count)"
    $listed = @(if ($whatIfLine.Count -eq 1) { [regex]::Matches($whatIfLine[0], '`([A-Z][A-Za-z]+-[A-Za-z]+)`') | ForEach-Object { $_.Groups[1].Value } }) | Sort-Object
    Assert-Equal 'static: scripts declaring SupportsShouldProcess = scripts the README lists for -WhatIf' $declared $listed
    #endregion

    #region Static: other claims checked from the source
    $readmeText = [System.IO.File]::ReadAllText((Join-Path $repoRoot 'README.md'))
    foreach ($file in $scriptFiles) {
        Assert-True "static: README links scripts/$($file.Name)" ($readmeText.Contains("(./scripts/$($file.Name))"))
    }

    # Comment-based help: synopsis, description, examples and every declared parameter
    foreach ($file in $scriptFiles) {
        $ast  = $asts[$file.BaseName]
        $help = $ast.GetHelpContent()
        $declaredParams = @($ast.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
        $documented = if ($help) { @($help.Parameters.Keys) } else { @() }
        $undocumented = @($declaredParams | Where-Object { $_ -notin $documented })
        $hasBasics = [bool]($help -and $help.Synopsis -and $help.Description -and $help.Examples.Count -gt 0)
        Assert-True "static: $($file.Name) help has synopsis, description, examples and every parameter" ($hasBasics -and $undocumented.Count -eq 0) ('undocumented: ' + ($undocumented -join ', '))
    }

    # Convert-RegistryToGPO only converts a file to a file: no registry or Group Policy write
    $regAst = $asts['Convert-RegistryToGPO']
    $forbiddenCommands = @('Set-ItemProperty', 'New-ItemProperty', 'Remove-ItemProperty', 'Set-Item', 'New-Item', 'Remove-Item',
                           'Import-GPO', 'New-GPO', 'Set-GPRegistryValue', 'Set-GPPrefRegistryValue', 'Start-Process',
                           'reg', 'reg.exe', 'regedit', 'regedit.exe', 'Invoke-Expression')
    $forbiddenMembers  = @('OpenSubKey', 'CreateSubKey', 'SetValue', 'DeleteValue', 'DeleteSubKey', 'DeleteSubKeyTree',
                           'OpenBaseKey', 'OpenRemoteBaseKey')
    $regCommands = @($regAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
        ForEach-Object { $_.GetCommandName() } | Where-Object { $_ -in $forbiddenCommands })
    $regMembers = @($regAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.InvokeMemberExpressionAst] }, $true) |
        ForEach-Object { $_.Member.Extent.Text } | Where-Object { $_ -in $forbiddenMembers })
    $regText = [System.IO.File]::ReadAllText((Join-Path $ScriptsPath 'Convert-RegistryToGPO.ps1'))
    $regDrives = @([regex]::Matches($regText, '(?i)\b(HKLM|HKCU|HKCR|HKU|HKCC):|Registry::') | ForEach-Object Value)
    Assert-True 'static: Convert-RegistryToGPO has no registry or Group Policy write' (($regCommands.Count + $regMembers.Count + $regDrives.Count) -eq 0) (($regCommands + $regMembers + $regDrives) -join ', ')

    # Password generators use a cryptographic generator, not Get-Random
    foreach ($name in 'Invoke-EmployeeOffboarding', 'Set-BulkUserOnboarding') {
        $text = [System.IO.File]::ReadAllText((Join-Path $ScriptsPath "$name.ps1"))
        Assert-True "static: $name does not use Get-Random" (-not ($text -match '(?i)\bGet-Random\b'))
        Assert-True "static: $name uses System.Security.Cryptography.RandomNumberGenerator" ($text.Contains('System.Security.Cryptography.RandomNumberGenerator'))
    }

    # Every command a script calls is a PowerShell built-in, a function the script defines, a
    # stub export or a runner replacement, so a newly used cmdlet fails here instead of reaching
    # a real module during a test run
    $builtIn = @{}
    Get-Command -Module 'Microsoft.PowerShell.Core', 'Microsoft.PowerShell.Utility', 'Microsoft.PowerShell.Management', 'Microsoft.PowerShell.Security' -ErrorAction SilentlyContinue |
        ForEach-Object { $builtIn[$_.Name] = $true }
    Get-Alias | ForEach-Object { $builtIn[$_.Name] = $true }
    $covered = @{}
    foreach ($manifest in Get-ChildItem -LiteralPath $stubRoot -Filter '*.psd1' -Recurse) {
        if ($manifest.BaseName -eq 'StubRecorder') { continue }
        foreach ($fn in @((Import-PowerShellDataFile -LiteralPath $manifest.FullName).FunctionsToExport)) { $covered[$fn] = $true }
    }
    $runnerTokens = $null; $runnerErrors = $null
    $runnerAst = [System.Management.Automation.Language.Parser]::ParseFile($runner, [ref]$runnerTokens, [ref]$runnerErrors)
    foreach ($fn in $runnerAst.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true)) {
        if ($fn.Name -like 'global:*') { $covered[$fn.Name.Substring(7)] = $true }
    }
    foreach ($file in $scriptFiles) {
        $ast = $asts[$file.BaseName]
        $own = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) | ForEach-Object Name)
        $called = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true) |
            Where-Object { -not (Test-InFilterScriptBlock $_) } |
            ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | Sort-Object -Unique)
        $uncovered = @($called | Where-Object { $_ -notin $own -and -not $builtIn.ContainsKey($_) -and -not $covered.ContainsKey($_) })
        Assert-True "static: $($file.Name) calls only built-ins, its own functions, stub exports and runner replacements" ($uncovered.Count -eq 0) ($uncovered -join ', ')
    }
    #endregion

    #region Password generators, tested from the scripts' own function definitions
    try {
        $offText = Get-ScriptFunctionText -Ast $asts['Invoke-EmployeeOffboarding'] -Name 'Get-SecureRandomIndex', 'New-RandomPassword'
        & {
            . ([scriptblock]::Create($offText))
            $passwords = @(1..20 | ForEach-Object { New-RandomPassword -Length 40 })
            Assert-True 'offboarding password: every one is 40 characters' (@($passwords | Where-Object { $_.Length -ne 40 }).Count -eq 0)
            Assert-True 'offboarding password: only printable ASCII 33-126, as before' (@($passwords | Where-Object { $_ -cnotmatch '^[!-~]+$' }).Count -eq 0)
            $all = -join $passwords
            Assert-True 'offboarding password: upper, lower, digit and symbol all occur over 20 passwords' (
                $all -cmatch '[A-Z]' -and $all -cmatch '[a-z]' -and $all -match '[0-9]' -and $all -match '[^A-Za-z0-9]')
            $distinct = [System.Collections.Generic.HashSet[string]]::new([string[]]$passwords, [System.StringComparer]::Ordinal)
            Assert-True 'offboarding password: 20 calls give 20 different passwords' ($distinct.Count -eq 20)

            $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $seen = @{}; $outOfRange = 0
            for ($i = 0; $i -lt 3000; $i++) {
                $v = Get-SecureRandomIndex -Rng $rng -MaxExclusive 94
                if ($v -lt 0 -or $v -ge 94) { $outOfRange++ }
                $seen[$v] = $true
            }
            $rng.Dispose()
            Assert-True 'secure index: 3000 draws below 94 stay in range and reach all 94 values' ($outOfRange -eq 0 -and $seen.Count -eq 94) "out of range $outOfRange, distinct $($seen.Count)"
        }
    } catch {
        Assert-True 'offboarding password generator can be loaded from the script' $false $_.Exception.Message
    }

    try {
        $onText = Get-ScriptFunctionText -Ast $asts['Set-BulkUserOnboarding'] -Name 'Get-SecureRandomIndex', 'New-TemporaryPassword'
        & {
            . ([scriptblock]::Create($onText))
            $sets = [ordered]@{
                Upper   = @{ Chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ'; Count = 3 }
                Lower   = @{ Chars = 'abcdefghjkmnpqrstuvwxyz'; Count = 3 }
                Digit   = @{ Chars = '23456789'; Count = 3 }
                Special = @{ Chars = '!@#$%^&*'; Count = 2 }
            }
            $passwords = @(1..50 | ForEach-Object { New-TemporaryPassword })
            Assert-True 'onboarding password: every one is 11 characters' (@($passwords | Where-Object { $_.Length -ne 11 }).Count -eq 0)
            foreach ($setName in $sets.Keys) {
                $set = $sets[$setName]
                $wrong = @($passwords | Where-Object {
                    $p = $_
                    @($p.ToCharArray() | Where-Object { $set['Chars'].Contains([string]$_) }).Count -ne $set['Count']
                })
                Assert-True "onboarding password: exactly $($set['Count']) characters from the $setName set" ($wrong.Count -eq 0) ($wrong -join ' ')
            }
            $distinct = [System.Collections.Generic.HashSet[string]]::new([string[]]$passwords, [System.StringComparer]::Ordinal)
            Assert-True 'onboarding password: 50 calls give 50 different passwords' ($distinct.Count -eq 50)
        }
    } catch {
        Assert-True 'onboarding password generator can be loaded from the script' $false $_.Exception.Message
    }
    #endregion

    #region Convert-RegistryToGPO
    $regSource = Join-Path $dataRoot 'registry-sample.reg'
    $regContent = [System.IO.File]::ReadAllText($regSource)
    $regInputs = @(
        @{ Label = 'utf8';  Encoding = [System.Text.UTF8Encoding]::new($false) },
        @{ Label = 'utf16'; Encoding = [System.Text.UnicodeEncoding]::new($false, $true) }   # as regedit.exe writes it
    )
    foreach ($regInput in $regInputs) {
        $label = $regInput.Label
        $regDir = Join-Path $script:TempRoot "registry-input-$label"
        New-Item -ItemType Directory -Path $regDir | Out-Null
        $regPath = Join-Path $regDir 'sample.reg'
        $xmlPath = Join-Path $regDir 'Registry.xml'
        [System.IO.File]::WriteAllText($regPath, $regContent, $regInput.Encoding)
        $hashBefore = (Get-FileHash -LiteralPath $regPath -Algorithm SHA256).Hash

        $run = Invoke-Scenario -Name "registry-$label" -Script 'Convert-RegistryToGPO.ps1' -Arguments @{
            RegFilePath = $regPath; XmlOutputPath = $xmlPath; Action = 'R'; Description = 'Synthetic test import'
        }
        Assert-RanCleanly $run
        [string[]]$written = @(Get-ChildItem -LiteralPath $regDir -Recurse -Force | ForEach-Object Name)
        [System.Array]::Sort($written, [System.StringComparer]::Ordinal)
        Assert-Equal "registry-${label}: the run wrote only the named output file next to its input" @('Registry.xml', 'sample.reg') $written
        Assert-True "registry-${label}: input file unchanged" ((Get-FileHash -LiteralPath $regPath -Algorithm SHA256).Hash -eq $hashBefore)

        $doc = $null
        try { $doc = [xml][System.IO.File]::ReadAllText($xmlPath) } catch { }
        Assert-True "registry-${label}: output is well-formed XML" ($null -ne $doc)
        if ($null -eq $doc) { continue }

        $props = @{}
        foreach ($p in $doc.SelectNodes('//Registry/Properties')) {
            $key = if ($p.GetAttribute('name')) { $p.GetAttribute('name') } else { '(default)' }
            $props[$key] = $p
        }
        [string[]]$names = @($props.Keys)
        [System.Array]::Sort($names, [System.StringComparer]::Ordinal)
        Assert-Equal "registry-${label}: converted values (the deleted value is skipped)" `
            @('(default)', 'BinaryValue', 'DwordValue', 'ExpandValue', 'LongBinary', 'MultiValue', 'QwordValue', 'Second', 'StringValue') `
            $names

        $expected = [ordered]@{
            '(default)'   = @('REG_SZ', 'C:\Program Files\Contoso')
            'StringValue' = @('REG_SZ', 'Hello "quoted" world')
            'DwordValue'  = @('REG_DWORD', '0000002A')
            'QwordValue'  = @('REG_QWORD', '1122334455667788')
            'BinaryValue' = @('REG_BINARY', 'deadbeef')
            'LongBinary'  = @('REG_BINARY', '000102030405060708090a0b0c0d0e0f1011121314151617')
            'MultiValue'  = @('REG_MULTI_SZ', 'Alpha Beta')
            'ExpandValue' = @('REG_EXPAND_SZ', '%SystemRoot%\Logs')
            'Second'      = @('REG_SZ', 'value2')
        }
        foreach ($name in $expected.Keys) {
            if (-not $props.ContainsKey($name)) { continue }
            $p = $props[$name]
            $suffix = if ($name -eq 'QwordValue') { ' [control for the QWORD fix]' } elseif ($name -eq '(default)') { ' [default value unescaped]' } else { '' }
            Assert-Equal "registry-${label}: $name type and value$suffix" $expected[$name] @($p.GetAttribute('type'), $p.GetAttribute('value'))
        }
        if ($props.ContainsKey('(default)')) {
            Assert-Equal "registry-${label}: default value is flagged default=1" '1' $props['(default)'].GetAttribute('default')
        }
        if ($props.ContainsKey('MultiValue')) {
            Assert-Equal "registry-${label}: REG_MULTI_SZ items" @('Alpha', 'Beta') @($props['MultiValue'].SelectNodes('Values/Value') | ForEach-Object InnerText)
        }
        Assert-True "registry-${label}: every item has action R, hive HKEY_LOCAL_MACHINE and the description" (
            @($props.Values | Where-Object {
                $_.GetAttribute('action') -ne 'R' -or $_.GetAttribute('hive') -ne 'HKEY_LOCAL_MACHINE' -or
                $_.ParentNode.GetAttribute('descr') -ne 'Synthetic test import' }).Count -eq 0)
        $base = "/Collection[@name='HKEY_LOCAL_MACHINE']/Collection[@name='SOFTWARE']/Collection[@name='Contoso']"
        Assert-True "registry-${label}: nested key becomes a nested collection" ($null -ne $doc.SelectSingleNode("$base/Collection[@name='Toolkit']/Collection[@name='Sub']/Registry[@name='LongBinary']"))
        Assert-True "registry-${label}: sibling key becomes a sibling collection" ($null -ne $doc.SelectSingleNode("$base/Collection[@name='Other']/Registry[@name='Second']"))
        if ($props.ContainsKey('LongBinary')) {
            Assert-Equal "registry-${label}: key path of the nested value" 'SOFTWARE\Contoso\Toolkit\Sub' $props['LongBinary'].GetAttribute('key')
        }
    }
    #endregion

    #region Get-EntraGuestReport
    $guestCsv = Join-Path $script:TempRoot 'guests-out' 'EntraGuests.csv'
    $run = Invoke-Scenario -Name 'guests' -Script 'Get-EntraGuestReport.ps1' -DataFile 'guests.json' -Arguments @{
        ExportPath = $guestCsv; InactiveDays = 90; GroupMembershipThreshold = 5
    }
    Assert-RanCleanly $run
    Assert-NoStateChange $run
    $rows = @(if (Test-Path -LiteralPath $guestCsv) { Import-Csv -LiteralPath $guestCsv })
    Assert-Equal 'guests: report order is risk rank, then days since sign-in, then UPN [control for the risk-sort fix]' `
        @('guest-a', 'guest-b', 'guest-g', 'guest-h', 'guest-c', 'guest-f', 'guest-d', 'guest-j', 'guest-i', 'guest-e') `
        @($rows | ForEach-Object { 'guest-' + $_.UserPrincipalName.Substring(0, 1) })
    Assert-Equal 'guests: risk levels in report order' `
        @('Critical', 'High', 'Medium', 'Medium', 'Medium', 'Low', 'Low', 'Low', 'None', 'None') @($rows | ForEach-Object RiskLevel)
    $byUpn = @{}; foreach ($r in $rows) { $byUpn[$r.UserPrincipalName.Substring(0, 1)] = $r }
    $expectedFlags = [ordered]@{
        a = 'Has privileged role'
        b = 'Inactive >90 days | Never signed in | Member of 6 groups | Invitation not accepted'
        c = 'Inactive >90 days | Invitation not accepted'
        d = 'Inactive >90 days'
        e = ''
        f = 'Inactive >90 days'
        g = 'Inactive >90 days | Never signed in'
        h = 'Inactive >90 days | Never signed in'
        i = ''
        j = 'Inactive >90 days'
    }
    foreach ($k in $expectedFlags.Keys) {
        if ($byUpn.ContainsKey($k)) { Assert-Equal "guests: flags of guest-$k" $expectedFlags[$k] $byUpn[$k].RiskFlags }
        else { Assert-True "guests: guest-$k is in the report" $false }
    }
    if ($byUpn.ContainsKey('d') -and $byUpn.ContainsKey('e') -and $byUpn.ContainsKey('b')) {
        Assert-Equal 'guests: group counts for 1, 5 and 6 groups' @('1', '5', '6') @($byUpn['d'].GroupCount, $byUpn['e'].GroupCount, $byUpn['b'].GroupCount)
        Assert-Equal 'guests: never signed in shows Never and 9999 days' @('Never', '9999') @($byUpn['b'].LastSignIn, $byUpn['b'].DaysSinceLogin)
    }
    Assert-True 'guests: the member account is not in the guest report' (@($rows | Where-Object { $_.UserPrincipalName -like 'morgan*' }).Count -eq 0)
    $mgUserCall = @(Get-Calls $run 'Get-MgUser')
    Assert-True 'guests: Get-MgUser asked for guests only' ($mgUserCall.Count -eq 1 -and (Get-CallParameter $mgUserCall[0] 'Filter') -eq "userType eq 'Guest'")
    #endregion

    #region Get-M365LicenseReport
    $licDir = Join-Path $script:TempRoot 'licenses-out'
    $run = Invoke-Scenario -Name 'licenses' -Script 'Get-M365LicenseReport.ps1' -DataFile 'licenses.json' -Arguments @{
        ExportPath = $licDir; InactiveDays = 90; LicensePricing = @{ SPE_E3 = 10; ENTERPRISEPACK = 4 }
    }
    Assert-RanCleanly $run
    Assert-NoStateChange $run
    $skuFile   = @(Get-ChildItem -LiteralPath $licDir -Filter 'SKU_Summary_*.csv' -ErrorAction SilentlyContinue)
    $userFile  = @(Get-ChildItem -LiteralPath $licDir -Filter 'User_Licenses_*.csv' -ErrorAction SilentlyContinue)
    $wasteFile = @(Get-ChildItem -LiteralPath $licDir -Filter 'Inactive_Licensed_Users_*.csv' -ErrorAction SilentlyContinue)
    Assert-True 'licenses: three report files written' ($skuFile.Count -eq 1 -and $userFile.Count -eq 1 -and $wasteFile.Count -eq 1)
    if ($skuFile.Count -eq 1) {
        $skuRows = @(Import-Csv -LiteralPath $skuFile[0].FullName)
        Assert-Equal 'licenses: SKU summary total / assigned / available' `
            @('SPE_E3 10 8 2', 'ENTERPRISEPACK 20 5 15', 'VISIOCLIENT 5 0 5') `
            @($skuRows | ForEach-Object { "$($_.SkuPartNumber) $($_.Total) $($_.Assigned) $($_.Available)" })
    }
    if ($userFile.Count -eq 1) {
        $userRows = @(Import-Csv -LiteralPath $userFile[0].FullName)
        Assert-Equal 'licenses: licensed users only, one row each' `
            @('Jamie Active', 'Kai Dormant', 'Lee Never', 'Noor Unknownsku', 'Oak Dormant', 'Pat Edge') @($userRows | ForEach-Object DisplayName)
        Assert-Equal 'licenses: license names per user' `
            @('SPE_E3', 'SPE_E3; ENTERPRISEPACK', 'ENTERPRISEPACK', '', 'ENTERPRISEPACK', 'VISIOCLIENT') @($userRows | ForEach-Object Licenses)
        Assert-Equal 'licenses: license count per user' @('1', '2', '1', '0', '1', '1') @($userRows | ForEach-Object LicenseCount)
        Assert-Equal 'licenses: inactive flag per user (89 days active, 91 days inactive, never = inactive)' `
            @('False', 'True', 'True', 'False', 'True', 'False') @($userRows | ForEach-Object IsInactive)
        Assert-Equal 'licenses: estimated cost per user from the pricing table' @('10', '14', '4', '0', '4', '0') @($userRows | ForEach-Object EstimatedCost_USD)
        $lee = @($userRows | Where-Object DisplayName -eq 'Lee Never')
        Assert-Equal 'licenses: never signed in shows Never and 9999 days' @('Never', '9999') @($lee | ForEach-Object { $_.LastSignIn; $_.InactiveDays })
    }
    if ($wasteFile.Count -eq 1) {
        Assert-Equal 'licenses: inactive licensed users' @('Kai Dormant', 'Lee Never', 'Oak Dormant') @(Import-Csv -LiteralPath $wasteFile[0].FullName | ForEach-Object DisplayName)
    }
    Assert-True 'licenses: estimated monthly waste 14 + 4 + 4 = 22 USD' ($run.Stdout -match 'Estimated monthly waste: \$22 USD')
    #endregion

    #region Invoke-ConditionalAccessAudit
    $caCsv = Join-Path $script:TempRoot 'ca-out' 'CA_Audit.csv'
    $run = Invoke-Scenario -Name 'ca-policies' -Script 'Invoke-ConditionalAccessAudit.ps1' -DataFile 'ca-policies.json' -Arguments @{ ExportPath = $caCsv }
    Assert-RanCleanly $run
    Assert-NoStateChange $run
    $findings = @(if (Test-Path -LiteralPath $caCsv) { Import-Csv -LiteralPath $caCsv })
    $expectedChecks = [ordered]@{
        'ca-clean'           = @()
        'ca-report-only'     = @('Report-Only Mode')
        'ca-disabled'        = @('Policy Disabled')
        'ca-no-grant'        = @('No Grant Controls')
        'ca-no-mfa'          = @('No MFA or Device Compliance')
        'ca-exclude-all'     = @('Excludes All Users')
        'ca-many-exclusions' = @('High User Exclusion Count')
        'ca-ten-exclusions'  = @()
        'ca-all-apps'        = @('Legacy Auth Not Explicitly Targeted')
        'ca-guests'          = @('Guest Access Without MFA')
        'ca-guest-types-set'   = @('Guest Access Without MFA')
        'ca-guest-types-empty' = @()
        'ca-no-exclusions'   = @('All Users Without Exclusions')
        'ca-block-legacy'    = @()
        'ca-sign-in-risk'    = @()
        'ca-block-guests'    = @()
    }
    foreach ($policyId in $expectedChecks.Keys) {
        $actual = @($findings | Where-Object PolicyId -eq $policyId | ForEach-Object Check | Sort-Object)
        $what = if ($expectedChecks[$policyId].Count -eq 0) { 'no finding' } else { $expectedChecks[$policyId] -join ', ' }
        Assert-Equal "ca: $policyId gives $what" @($expectedChecks[$policyId] | Sort-Object) $actual
    }
    Assert-Equal 'ca: no tenant-level finding when legacy-auth and sign-in risk policies exist' @() @($findings | Where-Object PolicyId -eq 'N/A' | ForEach-Object Check)
    Assert-True 'ca: an enabled policy that blocks legacy clients suppresses No Legacy Auth Block Policy' (@($findings | Where-Object Check -eq 'No Legacy Auth Block Policy').Count -eq 0)

    foreach ($legacyCase in @(
            @{ Name = 'ca-legacy-report-only'; Data = 'ca-legacy-report-only.json'; What = 'a report-only block policy' },
            @{ Name = 'ca-legacy-not-block'; Data = 'ca-legacy-not-block.json'; What = 'an enabled policy that requires MFA instead of blocking' })) {
        $legacyCsv = Join-Path $script:TempRoot "$($legacyCase.Name)-out" 'CA_Audit.csv'
        $run = Invoke-Scenario -Name $legacyCase.Name -Script 'Invoke-ConditionalAccessAudit.ps1' -DataFile $legacyCase.Data -Arguments @{ ExportPath = $legacyCsv }
        Assert-RanCleanly $run
        $legacyFindings = @(if (Test-Path -LiteralPath $legacyCsv) { Import-Csv -LiteralPath $legacyCsv })
        Assert-True "$($legacyCase.Name): $($legacyCase.What) for legacy clients does not suppress No Legacy Auth Block Policy" (
            @($legacyFindings | Where-Object { $_.PolicyId -eq 'N/A' -and $_.Check -eq 'No Legacy Auth Block Policy' }).Count -eq 1)
    }

    $caCleanCsv = Join-Path $script:TempRoot 'ca-clean-out' 'CA_Audit.csv'
    $run = Invoke-Scenario -Name 'ca-clean-only' -Script 'Invoke-ConditionalAccessAudit.ps1' -DataFile 'ca-clean-only.json' -Arguments @{
        ExportPath = $caCleanCsv; TenantId = '00000000-0000-0000-0000-000000000001'
    }
    Assert-RanCleanly $run
    $cleanFindings = @(if (Test-Path -LiteralPath $caCleanCsv) { Import-Csv -LiteralPath $caCleanCsv })
    Assert-Equal 'ca-clean-only: the clean policy gives no finding' @() @($cleanFindings | Where-Object PolicyId -eq 'ca-clean' | ForEach-Object Check)
    Assert-Equal 'ca-clean-only: both tenant-level checks fire' @('No Legacy Auth Block Policy', 'No Sign-In Risk Policy') @($cleanFindings | Where-Object PolicyId -eq 'N/A' | ForEach-Object Check | Sort-Object)
    $connect = @(Get-Calls $run 'Connect-MgGraph')
    Assert-True 'ca-clean-only: -TenantId is passed to Connect-MgGraph' ($connect.Count -eq 1 -and (Get-CallParameter $connect[0] 'TenantId') -eq '00000000-0000-0000-0000-000000000001')
    #endregion

    #region Find-StaleAccounts
    $staleCsv = Join-Path $script:TempRoot 'stale-out' 'Stale.csv'
    $staleArgs = @{ DaysInactive = 60; ExportPath = $staleCsv; ExcludeGroups = @('Svc-Exclude') }
    $run = Invoke-Scenario -Name 'stale-report' -Script 'Find-StaleAccounts.ps1' -DataFile 'stale-accounts.json' -Arguments $staleArgs
    Assert-RanCleanly $run
    Assert-NoStateChange $run
    $staleRows = @(if (Test-Path -LiteralPath $staleCsv) { Import-Csv -LiteralPath $staleCsv })
    Assert-Equal 'stale-report: stale accounts and their notes' `
        @('avery.stale: Inactive in AD and EXO', 'dana.nomailbox: No Exchange Online mailbox', 'eli.noexologon: No EXO logon recorded') `
        @($staleRows | ForEach-Object { "$($_.SamAccountName): $($_.Notes)" })
    Assert-True 'stale-report: 59 days in AD is not stale, 61 days is' (
        @($staleRows | Where-Object SamAccountName -eq 'casey.recent').Count -eq 0 -and @($staleRows | Where-Object SamAccountName -eq 'avery.stale').Count -eq 1)
    Assert-True 'stale-report: 61 days in AD but 59 days in Exchange Online is not stale' (@($staleRows | Where-Object SamAccountName -eq 'blake.mailactive').Count -eq 0)
    Assert-True 'stale-report: member of an excluded group is left out' (@($staleRows | Where-Object SamAccountName -eq 'frankie.excluded').Count -eq 0)
    Assert-True 'stale-report: disabled account is left out' (@($staleRows | Where-Object SamAccountName -eq 'gray.disabled').Count -eq 0)
    Assert-True 'stale-report: no confirmation prompt without -Remediate' (@(Get-Calls $run 'Read-Host').Count -eq 0)

    $remediateArgs = $staleArgs.Clone(); $remediateArgs['Remediate'] = $true; $remediateArgs['DisabledOU'] = 'OU=Disabled,DC=contoso,DC=com'
    $whatIfArgs = $remediateArgs.Clone(); $whatIfArgs['WhatIf'] = $true
    $run = Invoke-Scenario -Name 'stale-remediate-whatif' -Script 'Find-StaleAccounts.ps1' -DataFile 'stale-accounts.json' -Arguments $whatIfArgs -ReadHostAnswer 'CONFIRM'
    Assert-RanCleanly $run
    Assert-NoStateChange $run

    $run = Invoke-Scenario -Name 'stale-remediate-declined' -Script 'Find-StaleAccounts.ps1' -DataFile 'stale-accounts.json' -Arguments $remediateArgs -ReadHostAnswer 'no'
    Assert-RanCleanly $run
    Assert-NoStateChange $run

    $run = Invoke-Scenario -Name 'stale-remediate' -Script 'Find-StaleAccounts.ps1' -DataFile 'stale-accounts.json' -Arguments $remediateArgs -ReadHostAnswer 'CONFIRM'
    Assert-RanCleanly $run
    Assert-NoDelete $run
    Assert-Equal 'stale-remediate: accounts disabled' @('avery.stale', 'dana.nomailbox', 'eli.noexologon') @(Get-Calls $run 'Disable-ADAccount' | ForEach-Object { Get-CallParameter $_ 'Identity' })
    Assert-Equal 'stale-remediate: accounts moved to the Disabled OU' `
        @('CN=Avery Stale,OU=Staff,DC=contoso,DC=com -> OU=Disabled,DC=contoso,DC=com', 'CN=Dana Nomailbox,OU=Staff,DC=contoso,DC=com -> OU=Disabled,DC=contoso,DC=com', 'CN=Eli Noexologon,OU=Staff,DC=contoso,DC=com -> OU=Disabled,DC=contoso,DC=com') `
        @(Get-Calls $run 'Move-ADObject' | ForEach-Object { "$(Get-CallParameter $_ 'Identity') -> $(Get-CallParameter $_ 'TargetPath')" })
    Assert-Equal 'stale-remediate: only disable and move change anything' @('Disable-ADAccount', 'Move-ADObject') @(Get-Calls $run $StateChanging | ForEach-Object Command | Sort-Object -Unique)
    #endregion

    #region Get-MailboxPermissionReport
    $mbxCsv = Join-Path $script:TempRoot 'mailbox-all' 'MailboxPermissions.csv'
    $run = Invoke-Scenario -Name 'mailbox-all' -Script 'Get-MailboxPermissionReport.ps1' -DataFile 'mailboxes.json' -Arguments @{
        MailboxType = 'All'; IncludeCalendar = $true; ExportPath = $mbxCsv
    }
    Assert-RanCleanly $run
    Assert-NoStateChange $run
    $mbxRows = @(if (Test-Path -LiteralPath $mbxCsv) { Import-Csv -LiteralPath $mbxCsv })
    Assert-Equal 'mailbox-all: rows match the synthetic delegations' `
        @('Alex Wilson|UserMailbox|FullAccess|bree.lopez@contoso.com|FullAccess',
          'Alex Wilson|UserMailbox|SendAs|bree.lopez@contoso.com|SendAs',
          'Alex Wilson|UserMailbox|SendOnBehalf|Erin Hall|SendOnBehalf',
          'Alex Wilson|UserMailbox|CalendarFolder|Erin Hall|Editor',
          'Finance Shared|SharedMailbox|FullAccess|gus.clerk@contoso.com|FullAccess') `
        @($mbxRows | ForEach-Object { "$($_.Mailbox)|$($_.MailboxType)|$($_.PermissionType)|$($_.Delegate)|$($_.AccessRights)" })
    Assert-Equal 'mailbox-all: calendar read from <upn>:\Calendar' @('alex.wilson@contoso.com:\Calendar', 'finance@contoso.com:\Calendar') @(Get-Calls $run 'Get-MailboxFolderPermission' | ForEach-Object { Get-CallParameter $_ 'Identity' })

    $mbxCsv = Join-Path $script:TempRoot 'mailbox-shared' 'MailboxPermissions.csv'
    $run = Invoke-Scenario -Name 'mailbox-shared' -Script 'Get-MailboxPermissionReport.ps1' -DataFile 'mailboxes.json' -Arguments @{
        MailboxType = 'SharedMailbox'; ExportPath = $mbxCsv
    }
    Assert-RanCleanly $run
    $mbxRows = @(if (Test-Path -LiteralPath $mbxCsv) { Import-Csv -LiteralPath $mbxCsv })
    Assert-Equal 'mailbox-shared: only the shared mailbox' @('Finance Shared|FullAccess|gus.clerk@contoso.com') @($mbxRows | ForEach-Object { "$($_.Mailbox)|$($_.PermissionType)|$($_.Delegate)" })
    $exoCall = @(Get-Calls $run 'Get-EXOMailbox')
    Assert-True 'mailbox-shared: Get-EXOMailbox asked for SharedMailbox' ($exoCall.Count -eq 1 -and (@(Get-CallParameter $exoCall[0] 'RecipientTypeDetails') -join ',') -eq 'SharedMailbox')
    Assert-True 'mailbox-shared: no calendar lookup without -IncludeCalendar' (@(Get-Calls $run 'Get-MailboxFolderPermission').Count -eq 0)

    $mbxCsv = Join-Path $script:TempRoot 'mailbox-system' 'MailboxPermissions.csv'
    $run = Invoke-Scenario -Name 'mailbox-system' -Script 'Get-MailboxPermissionReport.ps1' -DataFile 'mailboxes.json' -Arguments @{
        ExcludeSystemAccounts = $false; ExportPath = $mbxCsv
    }
    Assert-RanCleanly $run
    $mbxRows = @(if (Test-Path -LiteralPath $mbxCsv) { Import-Csv -LiteralPath $mbxCsv })
    Assert-Equal 'mailbox-system: -ExcludeSystemAccounts:$false keeps system entries, SELF and inherited stay out' `
        @('FullAccess|bree.lopez@contoso.com', 'FullAccess|NT AUTHORITY\SYSTEM', 'FullAccess|S-1-5-21-1000-2000-3000-500',
          'SendAs|bree.lopez@contoso.com', 'SendOnBehalf|Erin Hall', 'FullAccess|gus.clerk@contoso.com') `
        @($mbxRows | ForEach-Object { "$($_.PermissionType)|$($_.Delegate)" })
    #endregion

    #region Export-ADUserAttributes
    $defaultColumns = @('SamAccountName', 'DisplayName', 'GivenName', 'Surname', 'EmailAddress', 'UserPrincipalName', 'EmployeeID',
                        'Department', 'Title', 'Manager', 'Description', 'Office', 'TelephoneNumber', 'Mobile', 'Enabled',
                        'LastLogonDate', 'PasswordNeverExpires', 'PasswordLastSet', 'Created', 'Modified', 'DistinguishedName', 'CanonicalName')
    $adCsv = Join-Path $script:TempRoot 'export-csv' 'ADUsers.csv'
    $run = Invoke-Scenario -Name 'export-csv' -Script 'Export-ADUserAttributes.ps1' -DataFile 'ad-users.json' -Arguments @{
        InputFilePath = (Join-Path $dataRoot 'employee-ids.csv'); OutputFilePath = $adCsv
    }
    Assert-RanCleanly $run
    Assert-NoStateChange $run
    $adRows = @(if (Test-Path -LiteralPath $adCsv) { Import-Csv -LiteralPath $adCsv })
    Assert-Equal 'export-csv: enabled users found by EmployeeID' @('E1001', 'E1003') @($adRows | ForEach-Object EmployeeID)
    if ($adRows.Count -ge 1) {
        Assert-Equal 'export-csv: columns are the default property list, in order' $defaultColumns @($adRows[0].PSObject.Properties.Name)
        $jane = $adRows[0]
        Assert-Equal 'export-csv: manager DN resolved to a SamAccountName' 'mia.garcia' $jane.Manager
        Assert-Equal 'export-csv: dates formatted' @('2026-03-15 09:30', '2026-02-01 08:15', '2023-07-03', '2026-03-02') @($jane.LastLogonDate, $jane.PasswordLastSet, $jane.Created, $jane.Modified)
        Assert-Equal 'export-csv: other attributes copied' @('Jane Example', 'jane.example@contoso.com', 'Analyst', '+1 555 0201', 'True') @($jane.DisplayName, $jane.EmailAddress, $jane.Title, $jane.Mobile, $jane.Enabled)
    }
    if ($adRows.Count -ge 2) {
        Assert-Equal 'export-csv: never logged on and no manager' @('Never', '', '') @($adRows[1].LastLogonDate, $adRows[1].Manager, $adRows[1].PasswordLastSet)
    }
    $notFound = Join-Path $script:TempRoot 'export-csv' 'ADUsers.notfound.txt'
    Assert-Equal 'export-csv: disabled and unknown IDs listed as not found' @('E1002', 'E9999') @(if (Test-Path -LiteralPath $notFound) { [System.IO.File]::ReadAllLines($notFound) | Where-Object { $_ } })
    $filters = @(Get-Calls $run 'Get-ADUser' | ForEach-Object { Get-CallParameter $_ 'Filter' } | Where-Object { $_ })
    Assert-True 'export-csv: filter by EmployeeID and Enabled' ($filters.Count -eq 4 -and $filters[0] -eq "EmployeeID -eq 'E1001' -and Enabled -eq `$true") ($filters -join ' || ')

    $adCsv = Join-Path $script:TempRoot 'export-disabled' 'ADUsers.csv'
    $run = Invoke-Scenario -Name 'export-disabled' -Script 'Export-ADUserAttributes.ps1' -DataFile 'ad-users.json' -Arguments @{
        InputFilePath = (Join-Path $dataRoot 'employee-ids.csv'); OutputFilePath = $adCsv; IncludeDisabled = $true
    }
    Assert-RanCleanly $run
    Assert-Equal 'export-disabled: -IncludeDisabled adds the disabled user' @('E1001', 'E1002', 'E1003') @(if (Test-Path -LiteralPath $adCsv) { Import-Csv -LiteralPath $adCsv | ForEach-Object EmployeeID })

    $adCsv = Join-Path $script:TempRoot 'export-txt' 'ADUsers.csv'
    $run = Invoke-Scenario -Name 'export-txt' -Script 'Export-ADUserAttributes.ps1' -DataFile 'ad-users.json' -Arguments @{
        InputFilePath = (Join-Path $dataRoot 'employee-ids.txt'); OutputFilePath = $adCsv
    }
    Assert-RanCleanly $run
    Assert-Equal 'export-txt: plain text input with one ID' @('lena.new') @(if (Test-Path -LiteralPath $adCsv) { Import-Csv -LiteralPath $adCsv | ForEach-Object SamAccountName })
    Assert-True 'export-txt: no not-found file when every ID is found' (-not (Test-Path -LiteralPath (Join-Path $script:TempRoot 'export-txt' 'ADUsers.notfound.txt')))
    #endregion

    #region Send-PasswordExpiryNotification
    $mailArgs = @{ SMTPServer = 'smtp.contoso.com'; FromAddress = 'it@contoso.com' }
    $whatIfArgs = $mailArgs.Clone(); $whatIfArgs['WhatIf'] = $true
    $run = Invoke-Scenario -Name 'expiry-whatif' -Script 'Send-PasswordExpiryNotification.ps1' -DataFile 'password-expiry.json' -Arguments $whatIfArgs
    Assert-RanCleanly $run
    Assert-NoStateChange $run
    $wouldNotify = @([regex]::Matches($run.Stdout, 'WHATIF \| Would notify: (\S+)') | ForEach-Object { $_.Groups[1].Value })
    Assert-Equal 'expiry-whatif: would notify at 14 and 2 days only' @('pat.fourteen', 'sky.two') $wouldNotify

    $expiryLog = Join-Path $script:TempRoot 'expiry-send' 'logs' 'PasswordExpiry.log'
    $sendArgs = $mailArgs.Clone(); $sendArgs['LogPath'] = $expiryLog
    $run = Invoke-Scenario -Name 'expiry-send' -Script 'Send-PasswordExpiryNotification.ps1' -DataFile 'password-expiry.json' -Arguments $sendArgs
    Assert-RanCleanly $run
    Assert-NoDelete $run
    $mails = @(Get-Calls $run 'Send-MailMessage')
    Assert-Equal 'expiry-send: mail recorded for 14 and 2 days, not 1, 3, 6, 7, 8, 13, 15, 16 days or a non-expiring password' `
        @('pat.fourteen@contoso.com', 'sky.two@contoso.com') @($mails | ForEach-Object { @(Get-CallParameter $_ 'To') -join ',' })
    Assert-Equal 'expiry-send: subjects' @('Action Required: Your password expires in 14 day(s)', 'Action Required: Your password expires in 2 day(s)') @($mails | ForEach-Object { Get-CallParameter $_ 'Subject' })
    Assert-True 'expiry-send: SMTP server, sender and HTML body passed to the (stubbed) Send-MailMessage' (
        @($mails | Where-Object { (Get-CallParameter $_ 'SmtpServer') -ne 'smtp.contoso.com' -or (Get-CallParameter $_ 'From') -ne 'it@contoso.com' -or -not (Get-CallParameter $_ 'BodyAsHtml') }).Count -eq 0)
    Assert-Equal 'expiry-send: only Send-MailMessage changes anything' @('Send-MailMessage') @(Get-Calls $run $StateChanging | ForEach-Object Command | Sort-Object -Unique)
    $logText = if (Test-Path -LiteralPath $expiryLog) { [System.IO.File]::ReadAllText($expiryLog) } else { '' }
    Assert-True 'expiry-send: log summary Notified 2, Skipped 9, Errors 0' ($logText -match 'Notified: 2 \| Skipped: 9 \| Errors: 0')

    $customArgs = $mailArgs.Clone(); $customArgs['DaysThreshold'] = @(15, 7)
    $run = Invoke-Scenario -Name 'expiry-custom' -Script 'Send-PasswordExpiryNotification.ps1' -DataFile 'password-expiry.json' -Arguments $customArgs
    Assert-RanCleanly $run
    Assert-Equal 'expiry-custom: -DaysThreshold 15,7 picks 15 and 7 days, not 14, 16, 6 or 8' `
        @('rae.fifteen@contoso.com', 'tay.seven@contoso.com') @(Get-Calls $run 'Send-MailMessage' | ForEach-Object { @(Get-CallParameter $_ 'To') -join ',' })
    #endregion

    #region Invoke-EmployeeOffboarding
    $offArgs = @{ SamAccountName = 'jordan.leaving'; DisabledOU = 'OU=Disabled Users,DC=contoso,DC=com'; AzureSyncWaitSeconds = 0 }

    $whatIfArgs = $offArgs.Clone(); $whatIfArgs['WhatIf'] = $true; $whatIfArgs['LogPath'] = (Join-Path $script:TempRoot 'offboarding-whatif' 'logs')
    $run = Invoke-Scenario -Name 'offboarding-whatif' -Script 'Invoke-EmployeeOffboarding.ps1' -DataFile 'offboarding.json' -Arguments $whatIfArgs
    Assert-RanCleanly $run
    Assert-NoStateChange $run
    Assert-NoDelete $run
    $announced = @('Disable AD account', 'Reset password to a random value', 'Remove from 2 group(s)', 'Clear manager, title and department',
                   'Move to OU=Disabled Users', 'Trigger delta sync', 'Convert mailbox to Shared', 'Grant Full Access to mia.garcia', 'Remove 1 license(s)')
    $missing = @($announced | Where-Object { -not $run.Stdout.Contains($_) })
    Assert-True 'offboarding-whatif: each of the nine changes is announced as What if' ($missing.Count -eq 0) ($missing -join '; ')

    $offLog = Join-Path $script:TempRoot 'offboarding-run' 'logs'
    $runArgs = $offArgs.Clone(); $runArgs['LogPath'] = $offLog
    $run = Invoke-Scenario -Name 'offboarding-run' -Script 'Invoke-EmployeeOffboarding.ps1' -DataFile 'offboarding.json' -Arguments $runArgs
    Assert-RanCleanly $run
    Assert-NoDelete $run
    $changes = @(Get-Calls $run $StateChanging)
    Assert-Equal 'offboarding-run: changes in the order the README lists them' `
        @('Disable-ADAccount', 'Set-ADAccountPassword', 'Remove-ADPrincipalGroupMembership', 'Set-ADUser', 'Move-ADObject',
          'Start-ADSyncSyncCycle', 'Set-Mailbox', 'Add-MailboxPermission', 'Set-MgUserLicense') @($changes | ForEach-Object Command)
    $c = @{}; foreach ($call in $changes) { $c[$call.Command] = $call }
    if ($c.Count -eq 9) {
        Assert-Equal 'offboarding-run: account disabled' 'jordan.leaving' (Get-CallParameter $c['Disable-ADAccount'] 'Identity')
        Assert-Equal 'offboarding-run: password reset with -Reset and a SecureString' @('True', '<SecureString>') @((Get-CallParameter $c['Set-ADAccountPassword'] 'Reset'), (Get-CallParameter $c['Set-ADAccountPassword'] 'NewPassword'))
        Assert-Equal 'offboarding-run: groups removed, Domain Users kept' @('CN=Finance-Team,OU=Groups,DC=contoso,DC=com', 'CN=VPN-Users,OU=Groups,DC=contoso,DC=com') @(Get-CallParameter $c['Remove-ADPrincipalGroupMembership'] 'MemberOf')
        Assert-Equal 'offboarding-run: manager, title and department cleared' @('', '', '') @((Get-CallParameter $c['Set-ADUser'] 'Manager'), (Get-CallParameter $c['Set-ADUser'] 'Title'), (Get-CallParameter $c['Set-ADUser'] 'Department'))
        Assert-Equal 'offboarding-run: moved to the Disabled OU' 'OU=Disabled Users,DC=contoso,DC=com' (Get-CallParameter $c['Move-ADObject'] 'TargetPath')
        Assert-Equal 'offboarding-run: delta sync' 'Delta' (Get-CallParameter $c['Start-ADSyncSyncCycle'] 'PolicyType')
        Assert-Equal 'offboarding-run: mailbox converted to Shared' @('jordan.leaving@contoso.com', 'Shared') @((Get-CallParameter $c['Set-Mailbox'] 'Identity'), (Get-CallParameter $c['Set-Mailbox'] 'Type'))
        Assert-Equal 'offboarding-run: manager from AD gets Full Access' @('mia.garcia', 'FullAccess') @((Get-CallParameter $c['Add-MailboxPermission'] 'User'), (@(Get-CallParameter $c['Add-MailboxPermission'] 'AccessRights') -join ','))
        Assert-Equal 'offboarding-run: the one license removed' '22222222-2222-2222-2222-222222222222' (@(Get-CallParameter $c['Set-MgUserLicense'] 'RemoveLicenses') -join ',')
    }
    $logFile = @(Get-ChildItem -LiteralPath $offLog -Filter 'jordan.leaving_*.log' -ErrorAction SilentlyContinue)
    $logText = if ($logFile.Count -eq 1) { [System.IO.File]::ReadAllText($logFile[0].FullName) } else { '' }
    Assert-True 'offboarding-run: log file written' ($logFile.Count -eq 1)
    Assert-True 'offboarding-run: log names each removed group with its DN [group-name fix]' (
        $logText.Contains('Removing from group: Finance-Team [CN=Finance-Team,OU=Groups,DC=contoso,DC=com]') -and
        $logText.Contains('Removing from group: VPN-Users [CN=VPN-Users,OU=Groups,DC=contoso,DC=com]') -and
        -not $logText.Contains('Removing from group: Domain Users'))
    Assert-True 'offboarding-run: license step logged as OK' ($logText.Contains('[Remove Licenses] [OK] 1 license(s) removed'))
    Assert-True 'offboarding-run: sync step OK with -AzureSyncWaitSeconds 0' ($logText.Contains('[Azure AD Sync] [OK]'))
    Assert-True 'offboarding-run: no failed step' (-not $logText.Contains('[FAILED]') -and $logText.Contains('Offboarding completed successfully'))
    Assert-True 'offboarding-run: no wait with -AzureSyncWaitSeconds 0' (@(Get-Calls $run 'Start-Sleep').Count -eq 0)

    $waitArgs = $offArgs.Clone(); $waitArgs['AzureSyncWaitSeconds'] = 2; $waitArgs['Manager'] = 'nora.lead'
    $waitArgs['LogPath'] = (Join-Path $script:TempRoot 'offboarding-manager' 'logs')
    $run = Invoke-Scenario -Name 'offboarding-manager' -Script 'Invoke-EmployeeOffboarding.ps1' -DataFile 'offboarding.json' -Arguments $waitArgs
    Assert-RanCleanly $run
    Assert-Equal 'offboarding-manager: -Manager overrides the AD manager' @('nora.lead') @(Get-Calls $run 'Add-MailboxPermission' | ForEach-Object { Get-CallParameter $_ 'User' })
    Assert-Equal 'offboarding-manager: waits 0..2 seconds in one-second steps (stubbed sleep)' 3 @(Get-Calls $run 'Start-Sleep').Count

    $missingArgs = $offArgs.Clone(); $missingArgs['SamAccountName'] = 'nobody.here'; $missingArgs['LogPath'] = (Join-Path $script:TempRoot 'offboarding-missing' 'logs')
    $run = Invoke-Scenario -Name 'offboarding-missing' -Script 'Invoke-EmployeeOffboarding.ps1' -DataFile 'offboarding.json' -Arguments $missingArgs
    Assert-RanCleanly $run -ExpectedExit 1
    Assert-NoStateChange $run
    #endregion

    #region Set-BulkUserOnboarding
    $onArgs = @{ CsvPath = (Join-Path $dataRoot 'new-hires.csv'); SMTPServer = 'smtp.contoso.com'; FromAddress = 'it@contoso.com'; DefaultGroups = @('All_Staff') }

    $whatIfArgs = $onArgs.Clone(); $whatIfArgs['WhatIf'] = $true; $whatIfArgs['LogPath'] = (Join-Path $script:TempRoot 'onboarding-whatif' 'logs')
    $run = Invoke-Scenario -Name 'onboarding-whatif' -Script 'Set-BulkUserOnboarding.ps1' -DataFile 'onboarding.json' -Arguments $whatIfArgs
    Assert-RanCleanly $run
    Assert-NoStateChange $run

    $onLog = Join-Path $script:TempRoot 'onboarding-run' 'logs'
    $runArgs = $onArgs.Clone(); $runArgs['LogPath'] = $onLog
    $run = Invoke-Scenario -Name 'onboarding-run' -Script 'Set-BulkUserOnboarding.ps1' -DataFile 'onboarding.json' -Arguments $runArgs
    Assert-RanCleanly $run
    Assert-NoDelete $run
    $newUsers = @(Get-Calls $run 'New-ADUser')
    Assert-Equal 'onboarding-run: accounts created (iivanov exists, so iivanov1)' @('jsmith', 'iivanov1') @($newUsers | ForEach-Object { Get-CallParameter $_ 'SamAccountName' })
    if ($newUsers.Count -eq 2) {
        Assert-Equal 'onboarding-run: UPN, path, title and e-mail of the first account' `
            @('jsmith@contoso.com', 'OU=Finance,DC=contoso,DC=com', 'Analyst', 'jane.smith@contoso.com', 'True', 'True') `
            @(foreach ($p in 'UserPrincipalName', 'Path', 'Title', 'EmailAddress', 'Enabled', 'ChangePasswordAtLogon') { Get-CallParameter $newUsers[0] $p })
        Assert-Equal 'onboarding-run: manager DN set from the CSV manager' 'CN=Mia Garcia,OU=Staff,DC=contoso,DC=com' (Get-CallParameter $newUsers[0] 'Manager')
        Assert-Equal 'onboarding-run: no e-mail in the CSV means the UPN is used' 'iivanov1@contoso.com' (Get-CallParameter $newUsers[1] 'EmailAddress')
    }
    Assert-Equal 'onboarding-run: default and CSV groups added' @('All_Staff:jsmith', 'Finance_DL:jsmith', 'VPN_Access:jsmith', 'All_Staff:iivanov1') `
        @(Get-Calls $run 'Add-ADGroupMember' | ForEach-Object { "$(Get-CallParameter $_ 'Identity'):$(Get-CallParameter $_ 'Members')" })
    Assert-Equal 'onboarding-run: one delta sync per user' 2 @(Get-Calls $run 'Start-ADSyncSyncCycle').Count
    Assert-Equal 'onboarding-run: license by SKU part number from the CSV' `
        @('jsmith@contoso.com:22222222-2222-2222-2222-222222222222', 'iivanov1@contoso.com:11111111-1111-1111-1111-111111111111') `
        @(Get-Calls $run 'Set-MgUserLicense' | ForEach-Object { "$(Get-CallParameter $_ 'UserId'):$((Get-CallParameter $_ 'AddLicenses').SkuId)" })
    $welcome = @(Get-Calls $run 'Send-MailMessage')
    Assert-Equal 'onboarding-run: welcome mail to each new user (recorded, not sent)' @('jane.smith@contoso.com', 'iivanov1@contoso.com') @($welcome | ForEach-Object { @(Get-CallParameter $_ 'To') -join ',' })
    $mailedPasswords = @($welcome | ForEach-Object { [regex]::Match((Get-CallParameter $_ 'Body'), 'Temporary Password</strong></td><td>([^<]+)</td>').Groups[1].Value })
    Assert-True 'onboarding-run: each welcome mail carries an 11-character temporary password' (@($mailedPasswords | Where-Object { $_.Length -ne 11 }).Count -eq 0 -and $mailedPasswords.Count -eq 2)
    Assert-True 'onboarding-run: the two temporary passwords differ' ($mailedPasswords.Count -eq 2 -and $mailedPasswords[0] -cne $mailedPasswords[1])
    $report = @(Get-ChildItem -LiteralPath $onLog -Filter 'OnboardingReport_*.csv' -ErrorAction SilentlyContinue)
    Assert-Equal 'onboarding-run: report shows both users OK' @('jsmith:OK', 'iivanov1:OK') @(if ($report.Count -eq 1) { Import-Csv -LiteralPath $report[0].FullName | ForEach-Object { "$($_.SamAccountName):$($_.Status)" } })
    $onLogFile = @(Get-ChildItem -LiteralPath $onLog -Filter 'Onboarding_*.log' -ErrorAction SilentlyContinue)
    $onLogText = if ($onLogFile.Count -eq 1) { [System.IO.File]::ReadAllText($onLogFile[0].FullName) } else { '' }
    Assert-True 'onboarding-run: summary line written' ($onLogText.Contains('=== Onboarding complete | Success: 2 | Partial: 0 ==='))

    $noGroupArgs = $onArgs.Clone(); $noGroupArgs['CsvPath'] = (Join-Path $dataRoot 'new-hires-no-groups.csv'); $noGroupArgs['LogPath'] = (Join-Path $script:TempRoot 'onboarding-no-groups' 'logs')
    $run = Invoke-Scenario -Name 'onboarding-no-groups' -Script 'Set-BulkUserOnboarding.ps1' -DataFile 'onboarding.json' -Arguments $noGroupArgs
    Assert-RanCleanly $run
    Assert-Equal 'onboarding-no-groups: a CSV without the optional Groups column works' @('All_Staff:iilic') `
        @(Get-Calls $run 'Add-ADGroupMember' | ForEach-Object { "$(Get-CallParameter $_ 'Identity'):$(Get-CallParameter $_ 'Members')" })

    $turkishLower = try { [System.Globalization.CultureInfo]::GetCultureInfo('tr-TR').TextInfo.ToLower('I') } catch { '' }
    if ($turkishLower -eq [string][char]0x0131) {
        $trArgs = $onArgs.Clone(); $trArgs['LogPath'] = (Join-Path $script:TempRoot 'onboarding-tr' 'logs')
        $run = Invoke-Scenario -Name 'onboarding-tr' -Script 'Set-BulkUserOnboarding.ps1' -DataFile 'onboarding.json' -Arguments $trArgs -Culture 'tr-TR'
        Assert-RanCleanly $run
        Assert-Equal 'onboarding-tr: account names do not depend on the culture (tr-TR)' @('jsmith', 'iivanov1') @(Get-Calls $run 'New-ADUser' | ForEach-Object { Get-CallParameter $_ 'SamAccountName' })
    } else {
        Write-Host 'SKIP  onboarding-tr: this .NET runtime has no Turkish casing data (invariant globalization)'
    }
    #endregion
} catch {
    Assert-True 'test run completed without an unexpected error' $false "$($_.Exception.Message) at line $($_.InvocationInfo.ScriptLineNumber)"
} finally {
    # Remove the temp folder; the guards keep the removal inside the folder this run created
    $resolvedTemp = [System.IO.Path]::GetFullPath($script:TempRoot)
    $resolvedBase = [System.IO.Path]::GetFullPath($tempBase)
    if ($resolvedTemp.StartsWith($resolvedBase) -and (Split-Path -Leaf $resolvedTemp) -like 'toolkit-tests-*' -and (Test-Path -LiteralPath $resolvedTemp)) {
        Remove-Item -LiteralPath $resolvedTemp -Recurse -Force
    }
}

Write-Host "RESULT: $script:Passed passed, $script:Failed failed"
exit $(if ($script:Failed -eq 0) { 0 } else { 1 })
