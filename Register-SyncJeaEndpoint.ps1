<#
.SYNOPSIS
    Registers a JEA (Just Enough Administration) endpoint on an Entra Connect
    server that exposes only the delta sync trigger and scheduler status, so
    onboarding techs never need admin remoting rights on a Tier 0 server.

.DESCRIPTION
    One-time setup. Run it ONCE, ON the Entra Connect server, in an elevated
    Windows PowerShell 5.1 session, as a local administrator. Connect to the
    server from a privileged access workstation (PAW).

    What it does:
    1. Creates a role-capability module that makes exactly two commands
       visible:
         - Start-ADSyncSyncCycle, with -PolicyType restricted to 'Delta'
         - Get-ADSyncScheduler (read-only status)
    2. Creates a session configuration:
         - SessionType RestrictedRemoteServer: no file system, no arbitrary
           script blocks, nothing beyond the visible commands
         - Runs as a virtual account by default (a temporary local admin that
           exists only for the session), so members of the allowed group need
           no standing rights on the server; or as a gMSA if specified
         - Writes a transcript of every session for auditing
    3. Registers the endpoint. Registration restarts WinRM, so existing
       remote sessions on the server drop briefly.

    Afterwards, members of the allowed group can run, from their own
    workstation:

        Invoke-Command -ComputerName entcon01.somedomainsomewhere.com `
            -ConfigurationName EntraConnect.SyncOps `
            -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }

    ...and nothing else on that server.

.PARAMETER AllowedPrincipal
    The AD group (DOMAIN\Group) whose members may connect to the endpoint.

.PARAMETER EndpointName
    Name of the session configuration. Default: EntraConnect.SyncOps

.PARAMETER RoleCapabilityName
    Name of the role-capability module. Default: EntraConnectSyncOps

.PARAMETER GroupManagedServiceAccount
    Optional gMSA (DOMAIN\name$) to run sessions as instead of a virtual
    account. It must be installed on this server and be a member of the local
    ADSyncAdmins group.

.PARAMETER TranscriptDirectory
    Directory for session transcripts. Default:
    C:\ProgramData\JEAConfiguration\Transcripts

.PARAMETER Uninstall
    Unregister the endpoint (the role-capability module is left in place).

.EXAMPLE
    .\Register-SyncJeaEndpoint.ps1 -AllowedPrincipal 'SOMEDOMAINSOMEWHERE\Onboarding-Provisioners' -WhatIf

    Shows what would be created, without making changes.

.EXAMPLE
    .\Register-SyncJeaEndpoint.ps1 -AllowedPrincipal 'SOMEDOMAINSOMEWHERE\Onboarding-Provisioners'

    Registers the endpoint, running sessions as a virtual account.

.EXAMPLE
    .\Register-SyncJeaEndpoint.ps1 -AllowedPrincipal 'SOMEDOMAINSOMEWHERE\Onboarding-Provisioners' -Uninstall

    Removes the endpoint.

.NOTES
    Author  : John O'Neill Sr.
    Company : Azure Innovators
    Website : https://www.azureinnovators.com
    Version : 1.0.0
    License : MIT

    Gotchas:
    - Register in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7.
      Remote clients connect to the default WinRM endpoint, which is Windows
      PowerShell.
    - In VisibleCmdlets, a hashtable entry needs both Name and Parameters. A
      command with no parameter limits must be listed as a plain string.
    - JEA limits what runs, not how WinRM authenticates. Workstations that
      aren't domain-joined still need TrustedHosts or an HTTPS listener.

    Change log:
    1.0.0 - 2026-10-11 - Initial public release
#>

[CmdletBinding(SupportsShouldProcess, PositionalBinding = $false)]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[^\\]+\\[^\\]+$')]
    [string]$AllowedPrincipal,

    [string]$EndpointName = 'EntraConnect.SyncOps',

    [string]$RoleCapabilityName = 'EntraConnectSyncOps',

    [string]$GroupManagedServiceAccount,

    [string]$TranscriptDirectory = 'C:\ProgramData\JEAConfiguration\Transcripts',

    [switch]$Uninstall
)

#Requires -Version 5.1
#Requires -RunAsAdministrator

$ErrorActionPreference = 'Stop'

if ($Uninstall) {
    if (-not (Get-PSSessionConfiguration -Name $EndpointName -ErrorAction SilentlyContinue)) {
        Write-Host "Endpoint '$EndpointName' is not registered. Nothing to do."
        return
    }
    if ($PSCmdlet.ShouldProcess($EndpointName, 'Unregister JEA endpoint (restarts WinRM)')) {
        Unregister-PSSessionConfiguration -Name $EndpointName -Force
        Write-Host "Endpoint '$EndpointName' unregistered." -ForegroundColor Green
    }
    return
}

# --- Pre-flight -------------------------------------------------------------------
if ($PSVersionTable.PSEdition -eq 'Core') {
    throw 'Run this in Windows PowerShell 5.1 (powershell.exe), not PowerShell 7, so the endpoint is registered where remote clients connect.'
}
if (-not (Get-Module -ListAvailable -Name ADSync)) {
    throw 'The ADSync module was not found. Run this ON the Entra Connect server.'
}
if ($GroupManagedServiceAccount) {
    Write-Warning "Sessions will run as '$GroupManagedServiceAccount'. It must be installed on this server and be a member of the local ADSyncAdmins group."
}

# --- Role capability ----------------------------------------------------------------
$moduleRoot = Join-Path $env:ProgramFiles "WindowsPowerShell\Modules\$RoleCapabilityName"
$roleCapDir = Join-Path $moduleRoot 'RoleCapabilities'
$psrcPath   = Join-Path $roleCapDir "$RoleCapabilityName.psrc"

if ($PSCmdlet.ShouldProcess($moduleRoot, 'Create JEA role-capability module')) {
    New-Item -ItemType Directory -Path $roleCapDir -Force | Out-Null
    New-ModuleManifest -Path (Join-Path $moduleRoot "$RoleCapabilityName.psd1") `
        -Description 'JEA role capability: Entra Connect delta sync trigger and scheduler status'

    # Exactly two visible commands; PolicyType locked to Delta.
    # A hashtable entry needs both Name and Parameters, so the unconstrained
    # command is listed as a plain string.
    New-PSRoleCapabilityFile -Path $psrcPath `
        -ModulesToImport 'ADSync' `
        -VisibleCmdlets @(
            @{ Name = 'Start-ADSyncSyncCycle'
               Parameters = @( @{ Name = 'PolicyType'; ValidateSet = 'Delta' } ) },
            'Get-ADSyncScheduler'
        ) `
        -Description 'Trigger an Entra Connect delta sync and read scheduler status. Nothing else.'
    Write-Host "Role capability created: $psrcPath" -ForegroundColor Green
}

# --- Session configuration --------------------------------------------------------------
$psscPath = Join-Path $env:ProgramData "JEAConfiguration\$EndpointName.pssc"

if ($PSCmdlet.ShouldProcess($EndpointName, 'Create JEA session configuration')) {
    New-Item -ItemType Directory -Path (Split-Path $psscPath) -Force | Out-Null
    New-Item -ItemType Directory -Path $TranscriptDirectory -Force | Out-Null

    $pssc = @{
        Path                = $psscPath
        SessionType         = 'RestrictedRemoteServer'
        TranscriptDirectory = $TranscriptDirectory
        RoleDefinitions     = @{ $AllowedPrincipal = @{ RoleCapabilities = $RoleCapabilityName } }
        Description         = 'Constrained endpoint: Entra Connect delta sync trigger only'
    }
    if ($GroupManagedServiceAccount) { $pssc.GroupManagedServiceAccount = $GroupManagedServiceAccount }
    else { $pssc.RunAsVirtualAccount = $true }

    New-PSSessionConfigurationFile @pssc
    if (-not (Test-PSSessionConfigurationFile -Path $psscPath)) {
        throw "Session configuration file failed validation: $psscPath"
    }
    Write-Host "Session configuration created and validated: $psscPath" -ForegroundColor Green
}

# --- Register ------------------------------------------------------------------------------
if (Get-PSSessionConfiguration -Name $EndpointName -ErrorAction SilentlyContinue) {
    if ($PSCmdlet.ShouldProcess($EndpointName, 'Unregister existing endpoint before re-registering')) {
        Unregister-PSSessionConfiguration -Name $EndpointName -Force
    }
}
if ($PSCmdlet.ShouldProcess($EndpointName, 'Register JEA endpoint (restarts WinRM)')) {
    Register-PSSessionConfiguration -Name $EndpointName -Path $psscPath -Force | Out-Null
    Write-Host "JEA endpoint '$EndpointName' registered." -ForegroundColor Green
}

Write-Host ''
Write-Host "Test from a workstation, as a member of $AllowedPrincipal :" -ForegroundColor Cyan
Write-Host "  Invoke-Command -ComputerName $env:COMPUTERNAME -ConfigurationName $EndpointName -ScriptBlock { Start-ADSyncSyncCycle -PolicyType Delta }"
Write-Host 'Negative tests (each must fail): connect without -ConfigurationName; -PolicyType Initial; any other command.'
Write-Host "Session transcripts: $TranscriptDirectory"
