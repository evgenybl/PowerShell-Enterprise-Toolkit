@{
    RootModule        = 'StubRecorder.psm1'
    ModuleVersion     = '0.0.1'
    GUID              = '6775ae49-bf07-4c7c-8fe7-8b0c55888c97'
    Description       = 'TEST STUB SUPPORT. Loads synthetic data and records stub calls. Contacts no real system.'
    FunctionsToExport = @('ConvertTo-StubObject', 'Get-StubData', 'Get-StubMapEntry', 'Write-StubCall', 'Test-StubIdentity', 'Select-StubByFilter')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
