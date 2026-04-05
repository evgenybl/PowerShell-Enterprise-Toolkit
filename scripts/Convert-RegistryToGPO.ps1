<#
.SYNOPSIS
    Converts a standard Windows .reg export file into a Group Policy Preferences Registry XML file.

.DESCRIPTION
    Convert-RegistryToGPO reads a .reg file and generates a settings.xml file in the format
    required by Group Policy Preferences (GPP) Registry extension. The output XML can be
    placed directly inside a GPO's Registry.xml path for deployment via Group Policy.

    This eliminates the need to manually recreate registry entries through the GPO editor
    when migrating settings captured with regedit.exe. Supports all standard registry
    value types: REG_SZ, REG_DWORD, REG_QWORD, REG_BINARY, REG_MULTI_SZ, REG_EXPAND_SZ.

    The function handles nested key paths and builds the correct Collection hierarchy
    required by the GPP XML schema.

.PARAMETER RegFilePath
    Path to the source .reg file exported from regedit.exe.

.PARAMETER XmlOutputPath
    Path for the output XML file. If not specified, the output is saved alongside the
    input file with a .xml extension.

.PARAMETER Action
    GPP action to apply. Valid values: U (Update), C (Create), R (Replace), D (Delete).
    Default is U (Update).

.PARAMETER Description
    Description string embedded in each Registry element. Default is "Imported from .reg file".

.EXAMPLE
    .\Convert-RegistryToGPO.ps1 -RegFilePath "C:\Exports\settings.reg"

.EXAMPLE
    .\Convert-RegistryToGPO.ps1 -RegFilePath "C:\Exports\settings.reg" -XmlOutputPath "C:\GPO\Registry.xml" -Action R

.NOTES
    Place the output XML at:
      \\<domain>\SYSVOL\<domain>\Policies\{GUID}\Machine\Preferences\Registry\Registry.xml

    Limitations:
      - All keys in a single .reg file must share the same hive root (HKLM or HKCU).
        Mixed hives are not supported by the GPP XML format.
      - Default values (@=) are supported for REG_SZ only.
#>

[CmdletBinding()]
param (
    [Parameter(Mandatory = $true)]
    [string]$RegFilePath,

    [Parameter(Mandatory = $false)]
    [string]$XmlOutputPath,

    [Parameter(Mandatory = $false)]
    [ValidateSet('U', 'C', 'R', 'D')]
    [string]$Action = 'U',

    [Parameter(Mandatory = $false)]
    [string]$Description = 'Imported from .reg file'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if (-not (Test-Path $RegFilePath)) {
    throw "Input file not found: $RegFilePath"
}

if (-not $XmlOutputPath) {
    $XmlOutputPath = [System.IO.Path]::ChangeExtension($RegFilePath, '.xml')
}

#region Internal helpers
function Convert-RegEscapeCodes {
    param ([string]$Value)
    return $Value.Replace('\\', '\').Replace('\"', '"')
}

function ConvertFrom-HexString {
    param ([string]$HexString)
    $bytes = New-Object byte[] ($HexString.Length / 2)
    for ($i = 0; $i -lt $HexString.Length; $i += 2) {
        $bytes[$i / 2] = [Convert]::ToByte($HexString.Substring($i, 2), 16)
    }
    return $bytes
}
#endregion

#region GPP CLSIDs
$clsidCollection = '{53B533F5-224C-47e3-B01B-CA3B3F3FF4BF}'
$clsidRegistry   = '{9CD4B2F4-923D-47f5-A062-E897DD1DAD50}'
#endregion

$xmlSettings            = New-Object System.Xml.XmlWriterSettings
$xmlSettings.Indent     = $true
$xmlSettings.Encoding   = [System.Text.Encoding]::UTF8
$xml                    = [System.Xml.XmlWriter]::Create($XmlOutputPath, $xmlSettings)
$unicoder               = New-Object System.Text.UnicodeEncoding

$lastHive       = ''
$lastKey        = ''
$collectionDepth = 0

$reader = New-Object System.IO.StreamReader($RegFilePath)

Write-Host "Converting: $RegFilePath" -ForegroundColor Cyan

try {
    while (-not $reader.EndOfStream) {
        $line = $reader.ReadLine()

        # Skip blank lines, comments, and the Windows Registry Editor header
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        if ($line.StartsWith(';'))               { continue }
        if ($line.StartsWith('Windows Registry')) { continue }

        #region Registry key line
        if ($line.StartsWith('[') -and $line.EndsWith(']')) {
            $fullKey     = $line.Substring(1, $line.Length - 2)
            $backslashIdx = $fullKey.IndexOf('\')
            $currentHive = $fullKey.Substring(0, $backslashIdx)
            $currentKey  = $fullKey.Substring($backslashIdx + 1)

            if ($lastHive -ne '' -and $currentHive -ne $lastHive) {
                throw "Mixed hives detected ('$lastHive' and '$currentHive'). GPP XML supports only one hive per file."
            }

            if ($lastHive -eq '') {
                # First key - open root collection
                $xml.WriteStartElement('Collection')
                $xml.WriteAttributeString('clsid', $clsidCollection)
                $xml.WriteAttributeString('name', $currentHive)
                $collectionDepth++

                foreach ($segment in $currentKey.Split('\')) {
                    $xml.WriteStartElement('Collection')
                    $xml.WriteAttributeString('clsid', $clsidCollection)
                    $xml.WriteAttributeString('name', $segment)
                    $collectionDepth++
                }
            } else {
                # Navigate relative to previous key
                $currentParts = $currentKey.Split('\')
                $lastParts    = $lastKey.Split('\')

                # Find common prefix length
                $commonLength = 0
                $minLength    = [Math]::Min($currentParts.Length, $lastParts.Length)
                for ($i = 0; $i -lt $minLength; $i++) {
                    if ($currentParts[$i] -eq $lastParts[$i]) { $commonLength++ } else { break }
                }

                # Close diverging collections
                $closeCount = $lastParts.Length - $commonLength
                for ($i = 0; $i -lt $closeCount; $i++) {
                    $xml.WriteEndElement()
                    $collectionDepth--
                }

                # Open new collections
                for ($i = $commonLength; $i -lt $currentParts.Length; $i++) {
                    $xml.WriteStartElement('Collection')
                    $xml.WriteAttributeString('clsid', $clsidCollection)
                    $xml.WriteAttributeString('name', $currentParts[$i])
                    $collectionDepth++
                }
            }

            $lastHive = $currentHive
            $lastKey  = $currentKey
            continue
        }
        #endregion

        #region Registry value line
        if ($line.Contains('=') -and $lastHive -ne '') {

            # Concatenate continuation lines
            while ($line.EndsWith('\')) {
                $line = $line.Substring(0, $line.Length - 1) + $reader.ReadLine().Trim()
            }

            $regType  = [Microsoft.Win32.RegistryValueKind]::Unknown
            $valueName = ''
            $value     = ''
            $isDefault = '0'

            # Detect type
            if ($line.StartsWith('@=') -or ($line.Contains('"') -and $line.Contains('"="'))) { $regType = [Microsoft.Win32.RegistryValueKind]::String }
            if ($line.Contains('=hex:'))     { $regType = [Microsoft.Win32.RegistryValueKind]::Binary }
            if ($line.Contains('=dword:'))   { $regType = [Microsoft.Win32.RegistryValueKind]::DWord }
            if ($line.Contains('=hex(7):'))  { $regType = [Microsoft.Win32.RegistryValueKind]::MultiString }
            if ($line.Contains('=hex(2):'))  { $regType = [Microsoft.Win32.RegistryValueKind]::ExpandString }
            if ($line.Contains('=hex(b):'))  { $regType = [Microsoft.Win32.RegistryValueKind]::QWord }

            if ($regType -eq [Microsoft.Win32.RegistryValueKind]::Unknown) { continue }

            switch ($regType) {
                ([Microsoft.Win32.RegistryValueKind]::String) {
                    if ($line.StartsWith('@=')) {
                        $valueName = ''
                        $value     = $line.Substring(3, $line.Length - 4)
                        $isDefault = '1'
                    } else {
                        $idx       = $line.IndexOf('"="')
                        $valueName = Convert-RegEscapeCodes $line.Substring(1, $idx - 1)
                        $value     = Convert-RegEscapeCodes $line.Substring($idx + 3, $line.Length - $idx - 4)
                    }

                    $xml.WriteStartElement('Registry')
                    $xml.WriteAttributeString('clsid', $clsidRegistry)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('descr', $Description)
                    $xml.WriteAttributeString('image', '7')
                    $xml.WriteStartElement('Properties')
                    $xml.WriteAttributeString('action', $Action)
                    $xml.WriteAttributeString('hive', $lastHive)
                    $xml.WriteAttributeString('key', $lastKey)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('default', $isDefault)
                    $xml.WriteAttributeString('type', 'REG_SZ')
                    $xml.WriteAttributeString('displayDecimal', '0')
                    $xml.WriteAttributeString('value', $value)
                    $xml.WriteEndElement()
                    $xml.WriteEndElement()
                }

                ([Microsoft.Win32.RegistryValueKind]::DWord) {
                    $idx       = $line.IndexOf('"=dword:')
                    $valueName = Convert-RegEscapeCodes $line.Substring(1, $idx - 1)
                    $value     = $line.Substring($idx + 8).ToUpper()

                    $xml.WriteStartElement('Registry')
                    $xml.WriteAttributeString('clsid', $clsidRegistry)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('descr', $Description)
                    $xml.WriteAttributeString('image', '17')
                    $xml.WriteStartElement('Properties')
                    $xml.WriteAttributeString('action', $Action)
                    $xml.WriteAttributeString('hive', $lastHive)
                    $xml.WriteAttributeString('key', $lastKey)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('default', '0')
                    $xml.WriteAttributeString('type', 'REG_DWORD')
                    $xml.WriteAttributeString('displayDecimal', '0')
                    $xml.WriteAttributeString('value', $value)
                    $xml.WriteEndElement()
                    $xml.WriteEndElement()
                }

                ([Microsoft.Win32.RegistryValueKind]::QWord) {
                    $idx       = $line.IndexOf('"=hex(b):')
                    $valueName = Convert-RegEscapeCodes $line.Substring(1, $idx - 1)
                    $tempHex   = $line.Substring($idx + 9).Replace(',', '').ToUpper()
                    $value     = ''
                    for ($i = $tempHex.Length - 2; $i -gt 0; $i -= 2) { $value += $tempHex.Substring($i, 2) }

                    $xml.WriteStartElement('Registry')
                    $xml.WriteAttributeString('clsid', $clsidRegistry)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('descr', $Description)
                    $xml.WriteAttributeString('image', '17')
                    $xml.WriteStartElement('Properties')
                    $xml.WriteAttributeString('action', $Action)
                    $xml.WriteAttributeString('hive', $lastHive)
                    $xml.WriteAttributeString('key', $lastKey)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('default', '0')
                    $xml.WriteAttributeString('type', 'REG_QWORD')
                    $xml.WriteAttributeString('displayDecimal', '0')
                    $xml.WriteAttributeString('value', $value)
                    $xml.WriteEndElement()
                    $xml.WriteEndElement()
                }

                ([Microsoft.Win32.RegistryValueKind]::Binary) {
                    $idx       = $line.IndexOf('"=hex:')
                    $valueName = Convert-RegEscapeCodes $line.Substring(1, $idx - 1)
                    $value     = $line.Substring($idx + 6).Replace(',', '')

                    $xml.WriteStartElement('Registry')
                    $xml.WriteAttributeString('clsid', $clsidRegistry)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('descr', $Description)
                    $xml.WriteAttributeString('image', '7')
                    $xml.WriteStartElement('Properties')
                    $xml.WriteAttributeString('action', $Action)
                    $xml.WriteAttributeString('hive', $lastHive)
                    $xml.WriteAttributeString('key', $lastKey)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('default', '0')
                    $xml.WriteAttributeString('type', 'REG_BINARY')
                    $xml.WriteAttributeString('displayDecimal', '0')
                    $xml.WriteAttributeString('value', $value)
                    $xml.WriteEndElement()
                    $xml.WriteEndElement()
                }

                ([Microsoft.Win32.RegistryValueKind]::MultiString) {
                    $idx       = $line.IndexOf('"=hex(7):')
                    $valueName = Convert-RegEscapeCodes $line.Substring(1, $idx - 1)
                    $hexValue  = $line.Substring($idx + 9).Replace(',', '')
                    $bytes     = ConvertFrom-HexString $hexValue
                    $multiStr  = $unicoder.GetString($bytes)
                    $values    = $multiStr.Replace("`0`0", '').Split("`0") | Where-Object { $_ }

                    $xml.WriteStartElement('Registry')
                    $xml.WriteAttributeString('clsid', $clsidRegistry)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('descr', $Description)
                    $xml.WriteAttributeString('image', '7')
                    $xml.WriteStartElement('Properties')
                    $xml.WriteAttributeString('action', $Action)
                    $xml.WriteAttributeString('hive', $lastHive)
                    $xml.WriteAttributeString('key', $lastKey)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('default', '0')
                    $xml.WriteAttributeString('type', 'REG_MULTI_SZ')
                    $xml.WriteAttributeString('displayDecimal', '0')
                    $xml.WriteAttributeString('value', ($values -join ' '))
                    $xml.WriteStartElement('Values')
                    foreach ($v in $values) {
                        $xml.WriteStartElement('Value')
                        $xml.WriteString($v)
                        $xml.WriteEndElement()
                    }
                    $xml.WriteEndElement()
                    $xml.WriteEndElement()
                    $xml.WriteEndElement()
                }

                ([Microsoft.Win32.RegistryValueKind]::ExpandString) {
                    $idx       = $line.IndexOf('"=hex(2):')
                    $valueName = Convert-RegEscapeCodes $line.Substring(1, $idx - 1)
                    $hexValue  = $line.Substring($idx + 9).Replace(',', '')
                    $bytes     = ConvertFrom-HexString $hexValue
                    $value     = $unicoder.GetString($bytes).Replace("`0", '')

                    $xml.WriteStartElement('Registry')
                    $xml.WriteAttributeString('clsid', $clsidRegistry)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('descr', $Description)
                    $xml.WriteAttributeString('image', '7')
                    $xml.WriteStartElement('Properties')
                    $xml.WriteAttributeString('action', $Action)
                    $xml.WriteAttributeString('hive', $lastHive)
                    $xml.WriteAttributeString('key', $lastKey)
                    $xml.WriteAttributeString('name', $valueName)
                    $xml.WriteAttributeString('default', '0')
                    $xml.WriteAttributeString('type', 'REG_EXPAND_SZ')
                    $xml.WriteAttributeString('displayDecimal', '0')
                    $xml.WriteAttributeString('value', $value)
                    $xml.WriteEndElement()
                    $xml.WriteEndElement()
                }
            }
        }
        #endregion
    }
} finally {
    $reader.Close()
    while ($collectionDepth -gt 0) {
        $xml.WriteEndElement()
        $collectionDepth--
    }
    $xml.Close()
}

Write-Host "Output saved: $XmlOutputPath" -ForegroundColor Green
