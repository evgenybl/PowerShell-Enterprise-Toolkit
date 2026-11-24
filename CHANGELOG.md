# Changelog

## 2026-11-24

### Fixed

- `Convert-RegistryToGPO`: a `REG_QWORD` value lost its first byte in conversion; all 8 bytes are now written.
- `Convert-RegistryToGPO`: escape sequences in a default value (`@="..."`) are now unescaped, as they already were for named values.
- `Invoke-ConditionalAccessAudit`: the help named three checks with no code. Two now run on data the policies already carry (all-users policies with no exclusion at all; no enabled sign-in risk policy); device compliance for privileged roles is listed as not checked.
- `Invoke-ConditionalAccessAudit`: block policies are no longer reported as `No MFA or Device Compliance` or `Guest Access Without MFA`.
- `Invoke-ConditionalAccessAudit`: the guest check now requires guest types in `IncludeGuestsOrExternalUsers`; the Graph SDK returns that property as an empty object when it is not set, which made the check fire on most policies without MFA.
- `Invoke-ConditionalAccessAudit`: only an enabled policy that blocks legacy clients now suppresses `No Legacy Auth Block Policy`; before, a disabled, report-only or non-blocking policy that named legacy clients also did.
- `Invoke-EmployeeOffboarding` and `Set-BulkUserOnboarding`: passwords come from `System.Security.Cryptography.RandomNumberGenerator` with rejection sampling instead of `Get-Random`; length and character classes are unchanged.
- `Invoke-EmployeeOffboarding`: `-WhatIf` now covers every step; before, only disabling the account checked it.
- `Invoke-EmployeeOffboarding`: the log names each removed group with its distinguished name.
- `Invoke-EmployeeOffboarding`: `-AzureSyncWaitSeconds 0` no longer marks the sync step as skipped through a division by zero.
- `Invoke-EmployeeOffboarding`: removing exactly one license was logged as a failed step.
- `Get-EntraGuestReport`: the report is sorted by risk rank (Critical first), then days since sign-in, then UPN, instead of by the risk label alphabetically.
- `Get-EntraGuestReport`: a guest in exactly one group was shown with a group count of 0.
- `Get-EntraGuestReport` and `Get-M365LicenseReport`: a user with no sign-in activity object no longer takes the previous user's sign-in date.
- `Get-M365LicenseReport`: a user with exactly one license got the previous user's row; every user now gets their own row.
- `Get-MailboxPermissionReport`: the `NT AUTHORITY` filter pattern never matched, so `NT AUTHORITY` accounts other than `SELF` were reported; they are now left out as documented.
- `Send-PasswordExpiryNotification`: a user whose expiry date cannot be computed (for example a password that does not expire) is skipped; before, the previous user's expiry date was reused and could trigger a reminder.
- `Set-BulkUserOnboarding`: a CSV without the optional `Groups` column no longer raises an error on every row.
- `Set-BulkUserOnboarding`: account names are lower-cased with the invariant culture; under tr-TR, `Ivan Ivanov` became `vanov`.
- `Set-BulkUserOnboarding`: the summary line was missing from the log when there were no `OK` rows or no `PARTIAL` rows.
- `Export-ADUserAttributes`, `Find-StaleAccounts`, `Get-EntraGuestReport`, `Get-MailboxPermissionReport`, `Invoke-ConditionalAccessAudit`, `Send-PasswordExpiryNotification`: a result of zero items or one item no longer raises a strict-mode error on `.Count`.
- Help text: `Invoke-EmployeeOffboarding` no longer lists MSOnline, `Set-BulkUserOnboarding` describes its first step as the code runs it, `Get-MailboxPermissionReport` says which inherited entries are left out, and `Convert-RegistryToGPO` names its output file correctly and lists deleted values as skipped.

### Changed

- README: status, script details, notes and known limitations rewritten to match the code and the tests; the instruction to place the `Convert-RegistryToGPO` output in SYSVOL as `Registry.xml` is removed, because that use has not been tested.

### Added

- `tests/Test-Toolkit.ps1`, with stub modules in `tests/stubs` and invented data in `tests/data`, and a GitHub Actions workflow that runs it on Windows and Linux.
