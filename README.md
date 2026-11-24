# PowerShell Enterprise Toolkit

[![tests](https://github.com/evgenybl/PowerShell-Enterprise-Toolkit/actions/workflows/tests.yml/badge.svg)](https://github.com/evgenybl/PowerShell-Enterprise-Toolkit/actions/workflows/tests.yml)

PowerShell scripts for Microsoft 365, Active Directory, Entra ID, Exchange Online and Group Policy administration.

Written from my years as a System Administrator in a hybrid Microsoft environment of about 2,000 users and 1,000 servers, in a three-person systems team. Each script addresses an operational task of that kind of environment.

**Status: reference code.** All ten scripts parse without errors and are checked by the automated tests described under [Tests](#tests), which run every script under stub modules against invented data. No script has been run against a live tenant, domain or mail server from this repository. Read a script and try it in a lab before you use it. Four scripts that change something support `-WhatIf`: `Find-StaleAccounts`, `Invoke-EmployeeOffboarding`, `Send-PasswordExpiryNotification` and `Set-BulkUserOnboarding`.

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
Install-Module ExchangeOnlineManagement
Install-Module Microsoft.Graph
```

The `ActiveDirectory` module is not installed with `Install-Module`. It comes with the Remote Server Administration Tools (RSAT):

```powershell
# Windows Server
Install-WindowsFeature -Name RSAT-AD-Tools -IncludeAllSubFeature
# Windows 10 or 11
Add-WindowsCapability -Online -Name Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0
```

The offboarding and onboarding scripts also call the `ADSync` module for their sync step. That step runs only on the Microsoft Entra Connect server; anywhere else it is skipped with a warning.

Run as an account with appropriate administrative rights in AD and/or Microsoft 365.

---

## Usage Pattern

The scripts that change something follow this pattern:

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
2. Resets the password to a random 40-character string from a cryptographic random number generator
3. Removes the user from all security and distribution groups
4. Clears manager, title, and department attributes
5. Moves the account to the Disabled OU
6. Triggers an Azure AD Connect delta sync
7. Waits for sync propagation
8. Converts the Exchange Online mailbox to Shared
9. Grants the manager Full Access to the shared mailbox
10. Removes all Microsoft 365 licenses
11. Prints a summary of the step results and writes a log file

With `-WhatIf`, each of these changes is announced and none is made.

```powershell
.\Invoke-EmployeeOffboarding.ps1 `
    -SamAccountName "jsmith" `
    -DisabledOU "OU=Disabled Users,DC=contoso,DC=com" `
    -Manager "mjones" `
    -AzureSyncWaitSeconds 90
```

---

### Find-StaleAccounts

Identifies inactive accounts by cross-referencing both AD `LastLogonDate` and Exchange Online `LastLogonTime`. Single-source checks produce false positives - a user may not log into Windows but still read email daily. This script catches both. With `-Remediate`, it asks you to type `CONFIRM`, then disables each reported account and moves it to `-DisabledOU`.

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

Converts a standard `.reg` file (exported from `regedit.exe`) into Group Policy Preferences style registry XML: a `Collection` tree with one `Registry` item per value. Whether Group Policy reads this output unchanged has not been tested; see [Known limitations](#known-limitations) before using it in a GPO. It reads the `.reg` file and writes the XML file; it does not read or change the registry or a GPO.

Supports: `REG_SZ`, `REG_DWORD`, `REG_QWORD`, `REG_BINARY`, `REG_MULTI_SZ`, `REG_EXPAND_SZ`

```powershell
.\Convert-RegistryToGPO.ps1 -RegFilePath "C:\Exports\settings.reg" -Action U
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

Retrieves all Conditional Access policies, runs 9 checks against each one and 2 tenant-level checks, and produces a severity-rated findings report.

**Checks:**
- Policies in Report-Only mode, and disabled policies
- Policies with no grant controls, or with grant controls that require neither MFA nor a compliant device (block policies are not flagged)
- Policies that exclude all users, or more than 10 individual users
- All-apps policies that do not target legacy authentication clients (Info)
- Guest or external users included without MFA (block policies are not flagged)
- Enabled policies that target all users and exclude no user, group or role, so no emergency-access account is excluded
- Tenant level: no enabled policy blocks legacy authentication clients; no enabled policy uses a sign-in risk condition (sign-in risk needs Microsoft Entra ID P2)

```powershell
.\Invoke-ConditionalAccessAudit.ps1 -ExportPath "C:\Audits\CA_Findings.csv"
```

---

### Get-EntraGuestReport

Inventories all Entra ID guest accounts and assigns a risk rating based on inactivity, privilege, group membership, and invitation status.

```powershell
.\Get-EntraGuestReport.ps1 -InactiveDays 90 -GroupMembershipThreshold 5
```

**Risk levels:** Critical / High / Medium / Low / None. A guest with any directory role assignment is Critical; otherwise three or more flags give High, two Medium, one Low. The report is sorted by risk level, highest first, then by days since the last sign-in.

---

### Set-BulkUserOnboarding

Processes a CSV of new employees and provisions each account end-to-end: creates the AD account, adds to groups, triggers Azure AD sync, assigns M365 license, and sends a welcome email with temporary credentials. The temporary password is written in that email in clear text; change the delivery if your policy does not allow it.

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

Exports all non-default mailbox delegations across Exchange Online. Covers Full Access, Send As, Send on Behalf, and optionally Calendar folder permissions. Filters out system accounts (`-ExcludeSystemAccounts:$false` keeps them) and inherited Full Access entries.

```powershell
# All mailboxes
.\Get-MailboxPermissionReport.ps1

# Shared mailboxes with calendar permissions
.\Get-MailboxPermissionReport.ps1 -MailboxType SharedMailbox -IncludeCalendar
```

---

## Tests

`tests/Test-Toolkit.ps1` checks the scripts without a tenant, a domain or a mail server.

- **Static checks:** every script parses; no script calls `Remove-ADUser`, `Remove-Mailbox`, `Remove-MgUser` or `Remove-AzureADUser`; the scripts that declare `SupportsShouldProcess` are exactly the four listed above for `-WhatIf`; every parameter is documented in the comment-based help; `Convert-RegistryToGPO` contains no registry or Group Policy write.
- **Runs under stubs:** each script runs in its own `pwsh` process with the stub modules in `tests/stubs`, which carry the names of `ActiveDirectory`, `ExchangeOnlineManagement`, `ADSync` and the `Microsoft.Graph` modules the scripts use. The stubs return invented data from `tests/data` (people at contoso.com and example.com, an invented tenant) and record every call; `Send-MailMessage` is replaced by a function that records the call and sends nothing. The tests check the report rows and figures, which accounts are flagged on each side of each threshold, that a `-WhatIf` run makes no state-changing call, which calls a real run would make, and the length and character classes of the generated passwords.
- **What the stubs cannot show:** how the real modules and services behave, including permissions, throttling, replication and sync delays, and the exact objects they return.

GitHub Actions runs the tests on Windows and on Linux for every push to `main` and every pull request; the badge at the top shows the latest result. No script has been run against a live tenant, domain or mail server from this repository.

### Run the tests

PowerShell 7 is required; nothing needs to be installed.

```powershell
pwsh -NoProfile -File tests/Test-Toolkit.ps1
```

It prints one line per check and ends with `RESULT: <passed> passed, <failed> failed`. The changes behind the current tests are listed in [CHANGELOG.md](./CHANGELOG.md).

---

## Development

The scripts were written with AI-assisted workflows (Claude, GitHub Copilot). The tests in `tests/` were written the same way.

---

## Notes

- The scripts delete no account and no mailbox. Some steps cannot be undone from the log alone: the offboarding script clears the manager, title and department, and its log does not record their old values. It does log each removed group by name and distinguished name. Export the attribute values first if you may need to restore them.
- Credentials are never hardcoded. The scripts have no `-Credential` parameter: the Active Directory cmdlets run as the signed-in user, and Exchange Online and Microsoft Graph sign in through `Connect-ExchangeOnline` and `Connect-MgGraph`.

## Known limitations

- `Send-PasswordExpiryNotification` and `Set-BulkUserOnboarding` send mail with `Send-MailMessage`, which Microsoft documents as obsolete.
- With `-WhatIf`, `Find-StaleAccounts`, `Invoke-EmployeeOffboarding`, `Send-PasswordExpiryNotification` and `Set-BulkUserOnboarding` also skip writing their own CSV and log files, although the console still prints the file path. A `-WhatIf` run still signs in and reads: `Invoke-EmployeeOffboarding` signs in to Exchange Online and Microsoft Graph, `Set-BulkUserOnboarding` signs in to Microsoft Graph, and `Find-StaleAccounts` connects to Exchange Online and, with `-Remediate`, still asks you to type `CONFIRM`.
- `Convert-RegistryToGPO` writes a tree whose root element is the hive's `Collection`, with no `uid` or `changed` attribute on the items. A `Registry.xml` written by the Group Policy editor has a `RegistrySettings` root element. Whether Group Policy reads this output unchanged as `Registry.xml` has not been tested here; compare it with a `Registry.xml` from one of your own GPOs first. Deleted values (`"name"=-`) are skipped and deleted keys (`[-HKEY_...]`) are not supported.
- `Invoke-ConditionalAccessAudit` does not check device compliance for privileged roles, because the policy objects do not say which roles are privileged. It reads only the built-in grant controls, custom factors and terms of use, and not session controls or authentication strengths. So a policy whose only grant control is an authentication strength is reported as `No Grant Controls`, a policy with only session controls is reported as `No Grant Controls`, and a guest policy that uses an authentication strength is reported as `Guest Access Without MFA`.
- `Find-StaleAccounts` selects accounts whose AD `LastLogonDate` is older than the threshold, so an account that has never logged on is not reported.
- `Invoke-EmployeeOffboarding` keeps the group named `Domain Users` and tries to remove every other group. If the user's primary group has another name (another language, or a changed primary group), the group removal step is logged as failed.
- `Set-BulkUserOnboarding` continues with groups, license and welcome email for a row whose AD account could not be created, and reports a row as `OK` when only a group membership or the welcome email failed. It does not shorten a `SamAccountName` longer than 20 characters, which Active Directory rejects. It assigns the license 10 seconds after requesting a sync and does not set a usage location, so the license step fails with a warning for a user that has not reached Entra ID yet or has no usage location.
- `Get-MailboxPermissionReport` reads calendar permissions from `<mailbox>:\Calendar`, so a mailbox whose calendar folder has another name (for example in another language) gives no calendar rows. Errors for a mailbox are written only to the verbose stream.

---

## Author

**Evgeny Blekhman** · [LinkedIn](https://www.linkedin.com/in/evgeny-blekhman/) · [GitHub](https://github.com/evgenybl)

AI & Automation Specialist. Practical AI training, workshops, business automation and integrations.
