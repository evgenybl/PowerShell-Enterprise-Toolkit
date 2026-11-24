@{
    RootModule        = 'ActiveDirectory.psm1'
    ModuleVersion     = '0.0.1'
    GUID              = '4885f593-1670-43fc-8850-0a9fc251cf11'
    Description       = 'TEST STUB with the name of the ActiveDirectory module. Records calls, returns synthetic data, contacts no domain.'
    FunctionsToExport = @('Get-ADUser', 'Get-ADGroupMember', 'Get-ADPrincipalGroupMembership', 'Get-ADDomain',
                          'Disable-ADAccount', 'Move-ADObject', 'Set-ADAccountPassword', 'Remove-ADPrincipalGroupMembership',
                          'Set-ADUser', 'New-ADUser', 'Add-ADGroupMember', 'Remove-ADUser')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
