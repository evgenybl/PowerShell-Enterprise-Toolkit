# TEST STUB SUPPORT. Shared by the stub modules in tests/stubs.
# Reads synthetic data from the JSON file named by $env:TOOLKIT_STUB_DATA and appends one
# JSON line per stub call to the file named by $env:TOOLKIT_STUB_LOG.
# Nothing in this folder contacts Active Directory, Exchange, Microsoft Graph, a mail server
# or the registry.

$script:Data     = $null
$script:DataPath = $null

function ConvertTo-StubObject {
    # Turns parsed JSON into objects that behave like the ones real modules return:
    # objects get a System.Object base (so .Count is not available on a single object under
    # strict mode, as with real module objects), and date markers become dates.
    param ($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [string]) {
        if ($Value -match '^@daysAgo:(-?\d+(?:\.\d+)?)$') {
            return (Get-Date).AddDays(-[double]::Parse($Matches[1], [cultureinfo]::InvariantCulture))
        }
        if ($Value -match '^@date:(.+)$') {
            return [datetime]::ParseExact($Matches[1], 'yyyy-MM-ddTHH:mm:ss', [cultureinfo]::InvariantCulture)
        }
        if ($Value -match '^@fileTimeDaysFromNow:(-?\d+)$') {
            return (Get-Date).Date.AddDays([int]$Matches[1]).AddHours(12).ToFileTime()
        }
        if ($Value -eq '@fileTimeMax') { return [long]::MaxValue }
        return $Value
    }
    if ($Value -is [System.Collections.IList]) {
        $list = @(foreach ($item in $Value) { ConvertTo-StubObject $item })
        return ,$list
    }
    if ($Value -is [System.Management.Automation.PSCustomObject]) {
        $obj = [psobject]::new([object]::new())
        foreach ($p in $Value.PSObject.Properties) {
            $obj | Add-Member -NotePropertyName $p.Name -NotePropertyValue (ConvertTo-StubObject $p.Value)
        }
        return $obj
    }
    return $Value
}

function Get-StubData {
    # Returns the named top-level entry of the current data file (arrays are unrolled).
    param ([Parameter(Mandatory)][string]$Name)
    $path = $env:TOOLKIT_STUB_DATA
    if (-not $path) { throw 'StubRecorder: TOOLKIT_STUB_DATA is not set.' }
    if ($script:DataPath -ne $path) {
        $raw = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
        $script:Data     = ConvertTo-StubObject $raw
        $script:DataPath = $path
    }
    if ($script:Data.PSObject.Properties[$Name]) { return $script:Data.$Name }
}

function Get-StubMapEntry {
    # Looks up Key in a JSON object used as a map (for example group name -> members).
    param ($Map, [string]$Key)
    if ($null -eq $Map) { return }
    $prop = $Map.PSObject.Properties | Where-Object { $_.Name -eq $Key } | Select-Object -First 1
    if ($prop) { return $prop.Value }
}

function ConvertTo-RecordValue {
    param ($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [System.Security.SecureString]) { return '<SecureString>' }
    if ($Value -is [System.Management.Automation.SwitchParameter]) { return [bool]$Value }
    if ($Value -is [scriptblock]) { return $Value.ToString().Trim() }
    if ($Value -is [string] -or $Value -is [ValueType]) { return $Value }
    if ($Value -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $Value.Keys) { $h[[string]$k] = ConvertTo-RecordValue $Value[$k] }
        return $h
    }
    if ($Value -is [System.Collections.IEnumerable]) {
        $items = @(foreach ($item in $Value) { ConvertTo-RecordValue $item })
        return ,$items
    }
    foreach ($n in 'DistinguishedName', 'SamAccountName', 'UserPrincipalName', 'Name', 'Id') {
        if ($Value.PSObject.Properties[$n]) { return [string]$Value.$n }
    }
    return [string]$Value
}

function Write-StubCall {
    # Appends {"Command": ..., "Parameters": {...}} as one JSON line to $env:TOOLKIT_STUB_LOG.
    param (
        [Parameter(Mandatory)][string]$Command,
        [System.Collections.IDictionary]$Parameters = @{}
    )
    $log = $env:TOOLKIT_STUB_LOG
    if (-not $log) { throw 'StubRecorder: TOOLKIT_STUB_LOG is not set.' }
    $params = [ordered]@{}
    foreach ($key in $Parameters.Keys) { $params[[string]$key] = ConvertTo-RecordValue $Parameters[$key] }
    $line = [ordered]@{ Command = $Command; Parameters = $params } | ConvertTo-Json -Depth 8 -Compress
    [System.IO.File]::AppendAllText($log, $line + "`n")
}

function Test-StubIdentity {
    # True when Object matches Identity by SamAccountName, DN, UPN, Name or Id.
    param ($Object, $Identity)
    $id = if ($Identity -is [string]) { $Identity }
          elseif ($Identity.PSObject.Properties['DistinguishedName']) { $Identity.DistinguishedName }
          else { [string]$Identity }
    foreach ($n in 'SamAccountName', 'DistinguishedName', 'UserPrincipalName', 'Name', 'Id') {
        if ($Object.PSObject.Properties[$n] -and $Object.$n -and ([string]$Object.$n) -eq $id) { return $true }
    }
    return $false
}

function Select-StubByFilter {
    # Evaluates an Active Directory or Exchange style filter ("Attr -op value -and ...") against
    # synthetic objects. Attribute names become property references; variables in the filter
    # are read from the caller of the stub, as the real modules do.
    param (
        [Parameter(Mandatory)]$Filter,
        [object[]]$Objects,
        [Parameter(Mandatory)][System.Management.Automation.SessionState]$CallerState
    )
    $filterText = if ($Filter -is [scriptblock]) { $Filter.ToString() } else { [string]$Filter }

    $tokens = $null; $parseErrors = $null
    $ast = [System.Management.Automation.Language.Parser]::ParseInput($filterText, [ref]$tokens, [ref]$parseErrors)
    $variables = @($ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.VariableExpressionAst] }, $true) |
        Where-Object { $_.VariablePath.UserPath -notin @('true', 'false', 'null', '_') } |
        Sort-Object { $_.Extent.StartOffset } -Descending)

    # Replace each variable with a private name and copy its value from the caller
    $rewritten = $filterText
    $values = @{}
    foreach ($v in $variables) {
        $name = $v.VariablePath.UserPath
        $private = "__stubvar_$name"
        $values[$private] = $CallerState.PSVariable.GetValue($name)
        $rewritten = $rewritten.Substring(0, $v.Extent.StartOffset) + '$' + $private + $rewritten.Substring($v.Extent.EndOffset)
    }
    $rewritten = [regex]::Replace($rewritten,
        '(?<=^|[\s(])([A-Za-z][A-Za-z0-9]*)(?=\s+-(?:eq|ne|lt|le|gt|ge|like|notlike)\b)',
        '$$_.$1', [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)

    foreach ($k in $values.Keys) { Set-Variable -Name $k -Value $values[$k] }
    $predicate = [scriptblock]::Create($rewritten)
    @($Objects) | Where-Object -FilterScript $predicate
}

Export-ModuleMember -Function ConvertTo-StubObject, Get-StubData, Get-StubMapEntry, Write-StubCall, Test-StubIdentity, Select-StubByFilter
