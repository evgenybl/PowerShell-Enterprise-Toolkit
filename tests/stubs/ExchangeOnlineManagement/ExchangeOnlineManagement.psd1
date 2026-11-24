@{
    RootModule        = 'ExchangeOnlineManagement.psm1'
    ModuleVersion     = '0.0.1'
    GUID              = '81ae88a1-ce88-471b-938a-4239de958876'
    Description       = 'TEST STUB with the name of the ExchangeOnlineManagement module. Records calls, returns synthetic data, contacts no tenant.'
    FunctionsToExport = @('Connect-ExchangeOnline', 'Disconnect-ExchangeOnline', 'Get-EXOMailbox', 'Get-EXOMailboxStatistics',
                          'Get-Mailbox', 'Get-MailboxPermission', 'Get-RecipientPermission', 'Get-MailboxFolderPermission',
                          'Set-Mailbox', 'Add-MailboxPermission', 'Remove-Mailbox')
    CmdletsToExport   = @()
    VariablesToExport = @()
    AliasesToExport   = @()
}
