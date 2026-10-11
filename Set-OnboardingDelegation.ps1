<#
.SYNOPSIS
    Creates a provisioning security group and delegates least-privilege
    user-onboarding rights on specific OUs, so onboarding no longer needs
    Domain Admin.

.DESCRIPTION
    One-time setup. Run it ONCE, as a Domain Admin (or an account that can
    modify the target OUs' security), from a privileged access workstation
    (PAW) with the RSAT Active Directory module. After that, members of the
    group can create and enable user accounts in the delegated OUs with their
    own standard accounts.

    What it does:
    1. Creates a global security group (default: Onboarding-Provisioners) if
       it doesn't already exist.
    2. On each target OU, grants that group exactly three rights:
         - Create user objects (in the OU and its sub-OUs)
         - Reset Password (extended right, on descendant user objects)
         - Generic Read + Generic Write on descendant user objects
           (display name, office, mail, description, userAccountControl to
           enable the account, pwdLastSet, and so on)
       The group cannot delete objects, change group membership, touch
       computers or GPOs, or affect anything outside the delegated OUs.
    3. With -Verify, prints the group's ACEs on each OU (read-only) so you can
       confirm or audit the delegation at any time.

    Safety check: GenericWrite on a user object includes attributes such as
    servicePrincipalName and msDS-KeyCredentialLink. That's acceptable for
    ordinary staff accounts, but never for privileged ones. The script refuses
    any target OU that contains accounts with adminCount=1 (members, past or
    present, of protected groups such as Domain Admins), unless you pass
    -AllowPrivilegedOU after reviewing them.

.PARAMETER TargetOUs
    One or more OU distinguished names to delegate onboarding rights on.

.PARAMETER GroupName
    Name of the provisioning security group. Default: Onboarding-Provisioners

.PARAMETER GroupPath
    Distinguished name of the OU in which to create the group. When omitted,
    the domain's default Users container is used.

.PARAMETER DomainController
    Specific domain controller to target. Auto-discovered when omitted.

.PARAMETER Verify
    Read-only: show the group's current ACEs on each target OU and exit.

.PARAMETER AllowPrivilegedOU
    Delegate even if a target OU contains adminCount=1 accounts. Don't use
    this unless you have reviewed those accounts and understand the risk.

.EXAMPLE
    .\Set-OnboardingDelegation.ps1 -TargetOUs 'OU=Users,OU=Staff,DC=somedomainsomewhere,DC=com' -WhatIf

    Shows what would be created and delegated, without making changes.

.EXAMPLE
    .\Set-OnboardingDelegation.ps1 `
        -TargetOUs 'OU=Users,OU=Staff,DC=somedomainsomewhere,DC=com',
                   'OU=Contractors,DC=somedomainsomewhere,DC=com' `
        -GroupPath 'OU=Groups,DC=somedomainsomewhere,DC=com'

    Creates the group in the Groups OU and delegates onboarding rights on two OUs.

.EXAMPLE
    .\Set-OnboardingDelegation.ps1 -TargetOUs 'OU=Users,OU=Staff,DC=somedomainsomewhere,DC=com' -Verify

    Lists what is currently delegated to the group (read-only).

.NOTES
    Author  : John O'Neill Sr.
    Company : Azure Innovators
    Website : https://www.azureinnovators.com
    Version : 1.0.0
    License : MIT

    Requires the RSAT ActiveDirectory module.
    Group members must sign out and back in (or wait for a Kerberos ticket
    refresh) before the new rights apply.

    Change log:
    1.0.0 - 2026-10-11 - Initial public release
#>

[CmdletBinding(SupportsShouldProcess, PositionalBinding = $false)]
param(
    [Parameter(Mandatory)]
    [string[]]$TargetOUs,

    [string]$GroupName = 'Onboarding-Provisioners',

    [string]$GroupPath,

    [string]$DomainController,

    [switch]$Verify,

    [switch]$AllowPrivilegedOU
)

#Requires -Version 5.1
#Requires -Modules ActiveDirectory

$ErrorActionPreference = 'Stop'

# Well-known schema and extended-right GUIDs
$UserClassGuid     = [Guid]'bf967aba-0de6-11d0-a285-00aa003049e2'  # user object class
$ResetPasswordGuid = [Guid]'00299570-246d-11d0-a768-00aa006e0529'  # Reset Password

$adParams = @{}
if ($DomainController) { $adParams.Server = $DomainController }

$domain = Get-ADDomain @adParams
Write-Verbose "Connected to domain '$($domain.DNSRoot)'."

# A dedicated AD drive, so ACL edits go to the same DC as everything else
$driveName = 'OnboardingDelegation'
if (Get-PSDrive -Name $driveName -ErrorAction SilentlyContinue) { Remove-PSDrive -Name $driveName -Force }
$driveParams = @{ Name = $driveName; PSProvider = 'ActiveDirectory'; Root = ''; WhatIf = $false }
if ($adParams.Server) { $driveParams.Server = $adParams.Server }
$null = New-PSDrive @driveParams

try {
    # --- Validate target OUs ---------------------------------------------------
    foreach ($ou in $TargetOUs) {
        $null = Get-ADOrganizationalUnit @adParams -Identity $ou
        Write-Verbose "Target OU found: $ou"
    }

    # --- Group ---------------------------------------------------------------------
    $group = Get-ADGroup @adParams -Filter "Name -eq '$GroupName'" -ErrorAction SilentlyContinue

    if ($Verify) {
        if (-not $group) { throw "Group '$GroupName' does not exist - nothing to verify." }
        foreach ($ou in $TargetOUs) {
            Write-Host "ACEs for '$GroupName' on: $ou" -ForegroundColor Cyan
            $aces = (Get-Acl -Path "$driveName`:\$ou").Access |
                Where-Object { $_.IdentityReference.Value -match "\\$([regex]::Escape($group.SamAccountName))$" }
            if (-not $aces) { Write-Warning '  (no ACEs found for this group)'; continue }
            foreach ($ace in $aces) {
                $object = switch ($ace.ObjectType) {
                    $UserClassGuid     { 'user objects' }
                    $ResetPasswordGuid { 'Reset Password' }
                    ([Guid]::Empty)    { 'all properties' }
                    default            { $ace.ObjectType }
                }
                $appliesTo = switch ($ace.InheritedObjectType) {
                    $UserClassGuid  { 'descendant user objects' }
                    ([Guid]::Empty) { 'this OU and descendants' }
                    default         { $ace.InheritedObjectType }
                }
                Write-Host ("  {0} | {1} | {2} | applies to {3}" -f
                    $ace.AccessControlType, $ace.ActiveDirectoryRights, $object, $appliesTo)
            }
        }
        return
    }

    # --- Safety check: no privileged accounts in delegated OUs -------------------
    foreach ($ou in $TargetOUs) {
        $privileged = @(Get-ADUser @adParams -SearchBase $ou -Filter 'adminCount -eq 1' -Properties adminCount)
        if ($privileged.Count -gt 0) {
            $names = ($privileged | Select-Object -First 10 -ExpandProperty SamAccountName) -join ', '
            $message = "OU '$ou' contains $($privileged.Count) account(s) with adminCount=1 ($names). " +
                       'Delegating Reset Password and GenericWrite there would let the group take over those accounts.'
            if ($AllowPrivilegedOU) { Write-Warning $message }
            else { throw "$message Move them to a separate OU, or re-run with -AllowPrivilegedOU after review." }
        }
    }

    if (-not $group) {
        if ($PSCmdlet.ShouldProcess($GroupName, 'Create security group')) {
            $newGroup = @{
                Name           = $GroupName
                SamAccountName = $GroupName
                GroupCategory  = 'Security'
                GroupScope     = 'Global'
                Description    = 'Delegated user onboarding: create users, reset passwords, write user attributes in delegated OUs only'
            }
            if ($GroupPath) { $newGroup.Path = $GroupPath }
            New-ADGroup @adParams @newGroup
            $group = Get-ADGroup @adParams -Identity $GroupName
            Write-Host "Created security group '$GroupName'." -ForegroundColor Green
        }
        else {
            Write-Host "WhatIf: would create group '$GroupName', then delegate on $($TargetOUs.Count) OU(s)."
            return
        }
    }

    $sid = [System.Security.Principal.SecurityIdentifier]$group.SID
    $R     = [System.DirectoryServices.ActiveDirectoryRights]
    $allow = [System.Security.AccessControl.AccessControlType]::Allow
    $all   = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::All
    $below = [System.DirectoryServices.ActiveDirectorySecurityInheritance]::Descendents

    # The three ACEs onboarding needs, and nothing more
    $rules = @(
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $sid, $R::CreateChild, $allow, $UserClassGuid, $all)
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $sid, $R::ExtendedRight, $allow, $ResetPasswordGuid, $below, $UserClassGuid)
        [System.DirectoryServices.ActiveDirectoryAccessRule]::new(
            $sid, ($R::GenericRead -bor $R::GenericWrite), $allow, $below, $UserClassGuid)
    )

    foreach ($ou in $TargetOUs) {
        if ($PSCmdlet.ShouldProcess($ou, "Delegate onboarding rights to '$GroupName'")) {
            $path = "$driveName`:\$ou"
            $acl = Get-Acl -Path $path
            foreach ($rule in $rules) { $acl.AddAccessRule($rule) }
            Set-Acl -Path $path -AclObject $acl
            Write-Host "Delegated onboarding rights on: $ou" -ForegroundColor Green
        }
    }

    Write-Host ''
    Write-Host 'Next steps:' -ForegroundColor Cyan
    Write-Host "  1. Add the help desk techs:  Add-ADGroupMember -Identity '$GroupName' -Members 'tech1','tech2'"
    Write-Host '  2. They sign out and back in before the rights apply.'
    Write-Host '  3. Re-run with -Verify at any time to audit the delegation.'
}
finally {
    Remove-PSDrive -Name $driveName -Force -WhatIf:$false -ErrorAction SilentlyContinue
}
