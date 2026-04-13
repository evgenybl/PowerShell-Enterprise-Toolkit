# PowerShell Enterprise Toolkit

Production-grade PowerShell scripts for Microsoft 365, Active Directory, Entra ID, Exchange Online, and Group Policy administration.

Built from 7+ years of hands-on enterprise IT work. These scripts were created and refined while managing a hybrid environment with 2,000+ users and 1,000 servers as part of a 6-person IT team (3 full-time, 3 part-time). Every script solves a real operational problem I ran into on the job, handles errors properly, supports `-WhatIf` where relevant, and produces auditable output.

---

## Scripts

| Script | Domain | Description |
|---|---|---|
| [Invoke-EmployeeOffboarding](./scripts/Invoke-EmployeeOffboarding.ps1) | AD + M365 | Full offboarding: disable, reset, remove groups, move OU, sync, convert mailbox, remove licenses |
| [Find-StaleAccounts](./scripts/Find-StaleAccounts.ps1) | AD + Exchange Online | Detects inactive accounts by cross-checking AD and Exchange Online activity |
| [Send-PasswordExpiryNotification](./scripts/Send-PasswordExpiryNotification.ps1) | AD | Sends HTML email reminders to users with expiring passwords |
| [Export-ADUserAttributes](./scripts/Export-ADUserAttributes.ps1) | AD | Bulk exports user attributes by EmployeeID list |
| [Convert-RegistryToGPO](./scripts/Convert-RegistryToGPO.ps1) | Group Policy | Converts .reg files to Group Policy Preferences Registry XML |
| [Get-M365LicenseReport](./scripts/Get-M365LicenseReport.ps1) | Microsoft 365 | License usage report with waste detection and cost estimation |
| [Invoke-ConditionalAccessAudit](./scripts/Invoke-ConditionalAccessAudit.ps1) | Entra ID | Audits all Conditional Access policies for security gaps |
| [Get-EntraGuestReport](./scripts/Get-EntraGuestReport.ps1) | Entra ID | Risk-rated inventory of all guest accounts with privilege detection |
| [Set-BulkUserOnboarding](./scripts/Set-BulkUserOnboarding.ps1) | AD + M365 | End-to-end bulk onboarding from CSV: AD account, groups, license, welcome email |
| [Get-MailboxPermissionReport](./scripts/Get-MailboxPermissionReport.ps1) | Exchange Online | Full mailbox delegation audit: FullAccess, SendAs, SendOnBehalf, Calendar |

---

## Requirements

Most scripts require one or more of these modules:

```powershell
Install-Module ActiveDirectory          # Built into Windows Server RSAT
Install-Module ExchangeOnlineManagement
Install-Module Microsoft.Graph
Install-Module MSOnline                 # Legacy, some scripts only
```

Run as an account with appropriate administrative rights in AD and/or Microsoft 365.

---

## Usage Pattern

All scripts follow a consistent pattern:

```powershell
# Preview changes without making them
.\Invoke-EmployeeOffboarding.ps1 -SamAccountName "jsmith" -DisabledOU "OU=Disabled,DC=contoso,DC=com" -WhatIf

# Execute
.\Invoke-EmployeeOffboarding.ps1 -SamAccountName "jsmith" -DisabledOU "OU=Disabled,DC=contoso,DC=com"
```

Every script includes full `Get-Help` documentation:

```powershell
Get-Help .\Invoke-EmployeeOffboarding.ps1 -Full
```

---

## Script Details

### Invoke-EmployeeOffboarding

Automates the complete offboarding workflow across AD and Microsoft 365.

**What it does:**
1. Disables the AD account
2. Resets the password to a cryptographically random 40-character string
3. Removes the user from all security and distribution groups
4. Clears manager, title, and department attributes
5. Moves the account to the Disabled OU
6. Triggers an Azure AD Connect delta sync
7. Waits for sync propagation
8. Converts the Exchange Online mailbox to Shared
9. Grants the manager Full Access to the shared mailbox
10. Removes all Microsoft 365 licenses
11. Runs a verification report and writes a log file

```powershell
.\Invoke-EmployeeOffboarding.ps1 `
    -SamAccountName "jsmith" `
    -DisabledOU "OU=Disabled Users,DC=contoso,DC=com" `
    -Manager "mjones" `
    -AzureSyncWaitSeconds 90
```

---

### Find-StaleAccounts

Identifies inactive accounts by cross-referencing both AD `LastLogonDate` and Exchange Online `LastLogonTime`. Single-source checks produce false positives - a user may not log into Windows but still read email daily. This script catches both.

```powershell
# Report only
.\Find-StaleAccounts.ps1 -DaysInactive 60 -ExportPath "C:\Reports\Stale.csv"

# Report and disable
.\Find-StaleAccounts.ps1 -DaysInactive 90 -Remediate -DisabledOU "OU=Disabled,DC=contoso,DC=com"
```

---

### Send-PasswordExpiryNotification

Queries AD for expiring passwords and sends HTML-formatted reminders at configurable intervals. Designed to run daily via Task Scheduler.

```powershell
.\Send-PasswordExpiryNotification.ps1 `
    -SMTPServer "smtp.contoso.com" `
    -FromAddress "it@contoso.com" `
    -DaysThreshold @(14, 7, 2) `
    -LogPath "C:\Logs\PasswordExpiry.log"
```

---

### Export-ADUserAttributes

Bulk-looks up AD users by EmployeeID from an HR export and produces a comprehensive attribute CSV. Accepts both CSV and plain text input.

```powershell
.\Export-ADUserAttributes.ps1 `
    -InputFilePath "C:\HR\employees.csv" `
    -OutputFilePath "C:\Reports\ADUsers.csv" `
    -IncludeDisabled
```

---

### Convert-RegistryToGPO

Converts a standard `.reg` file (exported from `regedit.exe`) into a `Registry.xml` file compatible with Group Policy Preferences. Eliminates manual re-entry in the GPO editor.

Supports: `REG_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`, `REG_MULTI_SZ`, `REG_EXPAND_SZ`

```powershell
.\Convert-RegistryToGPO.ps1 -RegFilePath "C:\Exports\settings.reg" -Action U
```

Place the output at:
```
\\domain\SYSVOL\domain\Policies\{GUID}\Machine\Preferences\Registry\Registry.xml
```

---

### Get-M365LicenseReport

Generates a full Microsoft 365 license inventory from Microsoft Graph. Flags licensed accounts with no recent sign-in activity as candidates for reclamation, and calculates estimated monthly waste if pricing is provided.

```powershell
$pricing = @{ 'SPE_E3' = 36; 'ENTERPRISEPACK' = 23 }
.\Get-M365LicenseReport.ps1 -InactiveDays 60 -LicensePricing $pricing
```

---

### Invoke-ConditionalAccessAudit

Retrieves all Conditional Access policies and runs 8 security checks against each one. Produces a severity-rated findings report.

**Checks include:**
- Policies in Report-Only mode
- Policies with no grant controls or no MFA requirement
- Broad user exclusions
- Guest access without MFA
- Missing legacy authentication block policy

```powershell
.\Invoke-ConditionalAccessAudit.ps1 -ExportPath "C:\Audits\CA_Findings.csv"
```

---

### Get-EntraGuestReport

Inventories all Entra ID guest accounts and assigns a risk rating based on inactivity, privilege, group membership, and invitation status.

```powershell
.\Get-EntraGuestReport.ps1 -InactiveDays 90 -GroupMembershipThreshold 5
```

**Risk levels:** Critical / High / Medium / Low / None

---

### Set-BulkUserOnboarding

Processes a CSV of new employees and provisions each account end-to-end: creates the AD account, adds to groups, triggers Azure AD sync, assigns M365 license, and sends a welcome email with temporary credentials.

```powershell
.\Set-BulkUserOnboarding.ps1 `
    -CsvPath "C:\HR\NewHires.csv" `
    -SMTPServer "smtp.contoso.com" `
    -FromAddress "it@contoso.com" `
    -DefaultGroups @("All_Staff", "VPN_Access")
```

CSV format:
```
FirstName,LastName,Department,JobTitle,Manager,OU,License,Email,Groups
Jane,Smith,Finance,Analyst,jdoe,"OU=Finance,DC=contoso,DC=com",ENTERPRISEPACK,jane.smith@contoso.com,"Finance_DL;VPN_Access"
```

---

### Get-MailboxPermissionReport

Exports all non-default mailbox delegations across Exchange Online. Covers Full Access, Send As, Send on Behalf, and optionally Calendar folder permissions. Filters out system and inherited permissions.

```powershell
# All mailboxes
.\Get-MailboxPermissionReport.ps1

# Shared mailboxes with calendar permissions
.\Get-MailboxPermissionReport.ps1 -MailboxType SharedMailbox -IncludeCalendar
```

---

## Development

Scripts are developed and enhanced using AI-assisted workflows (Claude, GitHub Copilot) for faster iteration, better error handling, and thorough documentation. All scripts are validated against real enterprise environments before publishing.

---

## Notes

- Scripts do not delete data. All destructive operations are reversible by an administrator.
- Credentials are never hardcoded. Use `-Credential` parameters, `Connect-*` module authentication, or a secrets manager.
- Tested against Exchange Online, Entra ID, and AD environments as of 2025–2026.

---

## Author

**Evgeny Blekhman**
Microsoft 365 & Azure Administrator | 7+ years enterprise IT | 2,000+ users, 1,000 servers
[LinkedIn](https://www.linkedin.com/in/evgeny-blekhman) · [GitHub](https://github.com/evgenybl)
