# Least-Privilege Onboarding Setup

One-time setup scripts that let a hybrid (on-prem AD + Microsoft Entra ID) onboarding process run as a **standard help desk account** instead of Domain Admin and Global Administrator.

These accompany the Azure Innovators article **[Onboarding Without the Master Key: The Least-Privilege Build](https://www.azureinnovators.com/)**, Part 2 of [Disabled Isn't Safe](https://www.azureinnovators.com/2026/10/10/disabled-admin-account-global-administrator-synced-ou/).

> **These are setup scripts, not an onboarding script.** Each one is run **once**, by an administrator, from a **privileged access workstation (PAW)**. What they build is what lets your day-to-day onboarding run without privileged credentials.

## What's here

| Script | Replaces | Run once, where | Run as |
| --- | --- | --- | --- |
| [`Set-OnboardingDelegation.ps1`](Set-OnboardingDelegation.ps1) | Domain Admin for creating users | From a PAW with the RSAT AD module | Domain Admin |
| [`Register-SyncJeaEndpoint.ps1`](Register-SyncJeaEndpoint.ps1) | Admin remoting to the Entra Connect server | On the Entra Connect server (reached from a PAW), elevated Windows PowerShell 5.1 | Local administrator on that server |

The article covers the remaining pieces, which are configured in the portals rather than scripted: a PIM-eligible Authentication Administrator role for Temporary Access Passes, group ownership for application groups, and Key Vault for the email secret.

## `Set-OnboardingDelegation.ps1`

Creates a security group (default `Onboarding-Provisioners`) and grants it exactly three rights on the OUs you choose:

1. Create user objects
2. Reset Password on user objects
3. Read and write user attributes (including `userAccountControl` to enable the account)

```powershell
# Preview
.\Set-OnboardingDelegation.ps1 -TargetOUs 'OU=Users,OU=Staff,DC=somedomainsomewhere,DC=com' -WhatIf

# Apply
.\Set-OnboardingDelegation.ps1 -TargetOUs 'OU=Users,OU=Staff,DC=somedomainsomewhere,DC=com' `
    -GroupPath 'OU=Groups,DC=somedomainsomewhere,DC=com'

# Audit later (read-only)
.\Set-OnboardingDelegation.ps1 -TargetOUs 'OU=Users,OU=Staff,DC=somedomainsomewhere,DC=com' -Verify
```

**Safety check:** the script refuses any OU that contains accounts with `adminCount=1`. Reset Password and `GenericWrite` over a privileged account would let the help desk take it over, so never delegate on OUs holding admin or service accounts. `-AllowPrivilegedOU` overrides this; don't use it without reviewing those accounts first.

Group members must sign out and back in before the new rights apply.

## `Register-SyncJeaEndpoint.ps1`

Registers a [Just Enough Administration](https://learn.microsoft.com/powershell/scripting/security/remoting/jea/overview) endpoint that exposes two commands and nothing else:

- `Start-ADSyncSyncCycle`, with `-PolicyType` limited to `Delta`
- `Get-ADSyncScheduler`

Sessions run as a temporary virtual account (or a gMSA), so the allowed group needs no standing rights on the server. Every session is transcribed.

```powershell
# On the Entra Connect server, elevated Windows PowerShell 5.1
.\Register-SyncJeaEndpoint.ps1 -AllowedPrincipal 'SOMEDOMAINSOMEWHERE\Onboarding-Provisioners'
```

Then, from a help desk workstation, as a member of that group:

```powershell
Invoke-Command -ComputerName 'entcon01.somedomainsomewhere.com' `
    -ConfigurationName 'EntraConnect.SyncOps' `
    -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }
```

Registration restarts WinRM, so existing remote sessions on the server drop briefly. Remove the endpoint with `-Uninstall`.

## Prove it

Least privilege isn't done until the things that *shouldn't* work don't. After setup, as a help desk account, each of these must fail:

- Remoting to the Entra Connect server **without** `-ConfigurationName`
- `Start-ADSyncSyncCycle -PolicyType Initial` through the endpoint
- Any other command through the endpoint (for example `Get-Process`)
- Creating a user in an OU outside the delegation

## Requirements

- Windows PowerShell 5.1 or later; the JEA script must run in Windows PowerShell 5.1
- RSAT Active Directory module (`Set-OnboardingDelegation.ps1`)
- Microsoft Entra Connect with the ADSync module (`Register-SyncJeaEndpoint.ps1`)

Test in a lab first. Both scripts support `-WhatIf`.

## License

[MIT](LICENSE) © 2026 John O'Neill Sr., [Azure Innovators](https://www.azureinnovators.com)

Questions, or want help adapting this to your environment? [Get in touch](https://www.azureinnovators.com/contact-us/).
