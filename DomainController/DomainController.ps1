#Requires -RunAsAdministrator
#Requires -Modules ADDSDeployment

<#
.SYNOPSIS
    DSC v3 resource for configuring Active Directory Domain Controllers
.DESCRIPTION
    This script implements a DSC v3 resource for promoting servers to domain controllers,
    supporting both primary domain controller (new forest) and additional domain controller scenarios.
.NOTES
    Author: DSC Administrator
    Version: 1.0.0
    Requires: PowerShell 7.x, Windows Server 2019+, ADDSDeployment module
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('get', 'set', 'test')]
    [string]$Operation
)

# Import required modules
Import-Module ADDSDeployment -Force -ErrorAction SilentlyContinue

#region Helper Functions

function Write-LogMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Warning', 'Error')]
        [string]$Level = 'Info'
    )
    
    $timestamp = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $logMessage = "[$timestamp] [$Level] $Message"
    
    switch ($Level) {
        'Info' { Write-Information $logMessage -InformationAction Continue }
        'Warning' { Write-Warning $logMessage }
        'Error' { Write-Error $logMessage }
    }
}

function Test-ADDSInstallation {
    <#
    .SYNOPSIS
        Tests if Active Directory Domain Services is installed
    #>
    try {
        $addsFeature = Get-WindowsFeature -Name AD-Domain-Services -ErrorAction SilentlyContinue
        return ($addsFeature -and $addsFeature.InstallState -eq 'Installed')
    }
    catch {
        Write-LogMessage "Error checking ADDS installation: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Test-DomainController {
    <#
    .SYNOPSIS
        Tests if the server is already a domain controller
    #>
    try {
        $domainRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
        # DomainRole: 4 = Backup Domain Controller, 5 = Primary Domain Controller
        return ($domainRole -eq 4 -or $domainRole -eq 5)
    }
    catch {
        Write-LogMessage "Error checking domain controller status: $($_.Exception.Message)" -Level Error
        return $false
    }
}

function Test-DomainExists {
    param([string]$DomainName)
    
    try {
        $domain = Get-ADDomain -Identity $DomainName -ErrorAction SilentlyContinue
        return ($null -ne $domain)
    }
    catch {
        return $false
    }
}

function Get-SafeModePasswordAsSecureString {
    param([string]$Password)
    
    return ConvertTo-SecureString -String $Password -AsPlainText -Force
}

function Get-DomainAdminCredential {
    param(
        [string]$Username,
        [string]$Password
    )
    
    if ([string]::IsNullOrEmpty($Username) -or [string]::IsNullOrEmpty($Password)) {
        return $null
    }
    
    $securePassword = ConvertTo-SecureString -String $Password -AsPlainText -Force
    return New-Object System.Management.Automation.PSCredential($Username, $securePassword)
}

#endregion

#region DSC Resource Functions

function Get-DomainControllerConfiguration {
    <#
    .SYNOPSIS
        Gets the current state of the domain controller configuration
    #>
    try {
        $result = @{
            ServerName = $env:COMPUTERNAME
            IsDomainController = Test-DomainController
            ADDSInstalled = Test-ADDSInstallation
            DomainName = $null
            Role = $null
        }
        
        if ($result.IsDomainController) {
            try {
                $domain = Get-ADDomain -Current LocalComputer -ErrorAction SilentlyContinue
                if ($domain) {
                    $result.DomainName = $domain.DNSRoot
                    
                    # Determine if this is the primary DC (PDC Emulator role holder)
                    $pdcEmulator = Get-ADDomain | Select-Object -ExpandProperty PDCEmulator
                    if ($pdcEmulator -eq $env:COMPUTERNAME) {
                        $result.Role = "PrimaryDomainController"
                    }
                    else {
                        $result.Role = "AdditionalDomainController"
                    }
                }
            }
            catch {
                Write-LogMessage "Error getting domain information: $($_.Exception.Message)" -Level Warning
            }
        }
        
        return $result | ConvertTo-Json -Depth 3
    }
    catch {
        Write-LogMessage "Error in Get-DomainControllerConfiguration: $($_.Exception.Message)" -Level Error
        throw
    }
}

function Test-DomainControllerConfiguration {
    <#
    .SYNOPSIS
        Tests if the domain controller is in the desired state
    #>
    param()
    
    try {
        # Read desired state from stdin
        $inputJson = [Console]::In.ReadToEnd()
        $desiredState = $inputJson | ConvertFrom-Json
        
        Write-LogMessage "Testing domain controller configuration for $($desiredState.ServerName)"
        
        # Check if ADDS is installed
        if (-not (Test-ADDSInstallation)) {
            Write-LogMessage "ADDS is not installed" -Level Info
            return @{ InDesiredState = $false; Reasons = @("ADDS feature not installed") } | ConvertTo-Json
        }
        
        # Check if server is a domain controller
        if (-not (Test-DomainController)) {
            Write-LogMessage "Server is not a domain controller" -Level Info
            return @{ InDesiredState = $false; Reasons = @("Server is not promoted to domain controller") } | ConvertTo-Json
        }
        
        # Check domain name
        try {
            $currentDomain = Get-ADDomain -Current LocalComputer -ErrorAction Stop
            if ($currentDomain.DNSRoot -ne $desiredState.DomainName) {
                Write-LogMessage "Domain name mismatch. Current: $($currentDomain.DNSRoot), Desired: $($desiredState.DomainName)" -Level Info
                return @{ InDesiredState = $false; Reasons = @("Domain name does not match") } | ConvertTo-Json
            }
        }
        catch {
            Write-LogMessage "Could not verify domain information: $($_.Exception.Message)" -Level Warning
            return @{ InDesiredState = $false; Reasons = @("Could not verify domain information") } | ConvertTo-Json
        }
        
        Write-LogMessage "Domain controller is in desired state"
        return @{ InDesiredState = $true; Reasons = @() } | ConvertTo-Json
    }
    catch {
        Write-LogMessage "Error in Test-DomainControllerConfiguration: $($_.Exception.Message)" -Level Error
        return @{ InDesiredState = $false; Reasons = @("Error during test: $($_.Exception.Message)") } | ConvertTo-Json
    }
}

function Set-DomainControllerConfiguration {
    <#
    .SYNOPSIS
        Configures the server as a domain controller
    #>
    param()
    
    try {
        # Read desired state from stdin
        $inputJson = [Console]::In.ReadToEnd()
        $desiredState = $inputJson | ConvertFrom-Json
        
        Write-LogMessage "Configuring domain controller: $($desiredState.ServerName)"
        
        # Install ADDS feature if not already installed
        if (-not (Test-ADDSInstallation)) {
            Write-LogMessage "Installing Active Directory Domain Services feature"
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Restart:$false
            
            # Verify installation
            if (-not (Test-ADDSInstallation)) {
                throw "Failed to install Active Directory Domain Services feature"
            }
        }
        
        # Convert password to secure string
        $safeModePassword = Get-SafeModePasswordAsSecureString -Password $desiredState.SafeModeAdministratorPassword
        
        # Configure based on role
        switch ($desiredState.Role) {
            "PrimaryDomainController" {
                Write-LogMessage "Configuring as Primary Domain Controller (new forest)"
                
                $installParams = @{
                    DomainName = $desiredState.DomainName
                    DomainNetbiosName = $desiredState.NetBIOSName
                    SafeModeAdministratorPassword = $safeModePassword
                    InstallDNS = $desiredState.InstallDNS -eq $true
                    Force = $true
                    NoRebootOnCompletion = $true
                }
                
                # Add optional parameters if specified
                if ($desiredState.ForestMode) {
                    $installParams.ForestMode = $desiredState.ForestMode
                }
                if ($desiredState.DomainMode) {
                    $installParams.DomainMode = $desiredState.DomainMode
                }
                if ($desiredState.DatabasePath) {
                    $installParams.DatabasePath = $desiredState.DatabasePath
                }
                if ($desiredState.LogPath) {
                    $installParams.LogPath = $desiredState.LogPath
                }
                if ($desiredState.SysvolPath) {
                    $installParams.SysvolPath = $desiredState.SysvolPath
                }
                
                Install-ADDSForest @installParams
            }
            
            "AdditionalDomainController" {
                Write-LogMessage "Configuring as Additional Domain Controller"
                
                # Get domain admin credential
                $domainAdminCred = Get-DomainAdminCredential -Username $desiredState.DomainAdministratorCredential.Username -Password $desiredState.DomainAdministratorCredential.Password
                
                if (-not $domainAdminCred) {
                    throw "Domain administrator credentials are required for additional domain controller"
                }
                
                $installParams = @{
                    DomainName = $desiredState.DomainName
                    SafeModeAdministratorPassword = $safeModePassword
                    Credential = $domainAdminCred
                    InstallDNS = $desiredState.InstallDNS -eq $true
                    Force = $true
                    NoRebootOnCompletion = $true
                }
                
                # Add optional parameters if specified
                if ($desiredState.DatabasePath) {
                    $installParams.DatabasePath = $desiredState.DatabasePath
                }
                if ($desiredState.LogPath) {
                    $installParams.LogPath = $desiredState.LogPath
                }
                if ($desiredState.SysvolPath) {
                    $installParams.SysvolPath = $desiredState.SysvolPath
                }
                
                Install-ADDSDomainController @installParams
            }
            
            default {
                throw "Invalid role specified: $($desiredState.Role)"
            }
        }
        
        Write-LogMessage "Domain controller configuration completed successfully"
        Write-LogMessage "A reboot is required to complete the configuration" -Level Warning
        
        return @{ 
            Status = "Success"
            Message = "Domain controller configured successfully. Reboot required."
            RebootRequired = $true
        } | ConvertTo-Json
    }
    catch {
        Write-LogMessage "Error in Set-DomainControllerConfiguration: $($_.Exception.Message)" -Level Error
        return @{ 
            Status = "Error"
            Message = $_.Exception.Message
            RebootRequired = $false
        } | ConvertTo-Json
    }
}

#endregion

#region Main Execution

try {
    switch ($Operation.ToLower()) {
        'get' {
            Get-DomainControllerConfiguration
        }
        'test' {
            Test-DomainControllerConfiguration
        }
        'set' {
            Set-DomainControllerConfiguration
        }
        default {
            throw "Invalid operation: $Operation"
        }
    }
}
catch {
    Write-LogMessage "Fatal error in domain controller resource: $($_.Exception.Message)" -Level Error
    exit 1
}

#endregion
