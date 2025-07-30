#Requires -Module Pester

<#
.SYNOPSIS
    Unit tests for the Domain Controller DSC v3 resource
.DESCRIPTION
    Tests the functionality of the DomainController resource without requiring actual AD deployment
#>

Describe "DomainController DSC Resource Tests" {
    BeforeAll {
        # Mock the required modules and functions
        Mock Import-Module { }
        Mock Get-WindowsFeature { 
            return @{ Name = "AD-Domain-Services"; InstallState = "Installed" }
        }
        Mock Get-WmiObject {
            return @{ DomainRole = 5 }  # Primary Domain Controller
        }
        Mock Get-ADDomain {
            return @{ 
                DNSRoot = "test.local"
                PDCEmulator = $env:COMPUTERNAME
            }
        }
        
        # Source the main script functions
        $scriptPath = Join-Path $PSScriptRoot ".." "DomainController" "DomainController.ps1"
        . $scriptPath
    }
    
    Context "Helper Functions" {
        Describe "Test-ADDSInstallation" {
            It "Should return true when ADDS is installed" {
                Mock Get-WindowsFeature { 
                    return @{ Name = "AD-Domain-Services"; InstallState = "Installed" }
                }
                
                Test-ADDSInstallation | Should -Be $true
            }
            
            It "Should return false when ADDS is not installed" {
                Mock Get-WindowsFeature { 
                    return @{ Name = "AD-Domain-Services"; InstallState = "Available" }
                }
                
                Test-ADDSInstallation | Should -Be $false
            }
        }
        
        Describe "Test-DomainController" {
            It "Should return true when server is a domain controller" {
                Mock Get-WmiObject {
                    return @{ DomainRole = 5 }  # Primary DC
                }
                
                Test-DomainController | Should -Be $true
            }
            
            It "Should return false when server is not a domain controller" {
                Mock Get-WmiObject {
                    return @{ DomainRole = 1 }  # Member Server
                }
                
                Test-DomainController | Should -Be $false
            }
        }
    }
    
    Context "DSC Resource Functions" {
        Describe "Get-DomainControllerConfiguration" {
            It "Should return current configuration as JSON" {
                $result = Get-DomainControllerConfiguration | ConvertFrom-Json
                
                $result.ServerName | Should -Be $env:COMPUTERNAME
                $result.IsDomainController | Should -Be $true
                $result.ADDSInstalled | Should -Be $true
                $result.DomainName | Should -Be "test.local"
                $result.Role | Should -Be "PrimaryDomainController"
            }
        }
        
        Describe "Test-DomainControllerConfiguration" {
            It "Should return InDesiredState true when configuration matches" {
                # Mock Console input
                $mockInput = @{
                    ServerName = $env:COMPUTERNAME
                    DomainName = "test.local"
                    Role = "PrimaryDomainController"
                } | ConvertTo-Json
                
                Mock -CommandName [Console]::In.ReadToEnd { return $mockInput }
                
                $result = Test-DomainControllerConfiguration | ConvertFrom-Json
                $result.InDesiredState | Should -Be $true
            }
        }
    }
    
    Context "Security Tests" {
        Describe "Password Handling" {
            It "Should convert plain text password to secure string" {
                $plainPassword = "TestPassword123!"
                $securePassword = Get-SafeModePasswordAsSecureString -Password $plainPassword
                
                $securePassword | Should -BeOfType [System.Security.SecureString]
            }
            
            It "Should create proper credential object" {
                $username = "TestUser"
                $password = "TestPassword123!"
                $credential = Get-DomainAdminCredential -Username $username -Password $password
                
                $credential | Should -BeOfType [System.Management.Automation.PSCredential]
                $credential.UserName | Should -Be $username
            }
        }
    }
    
    Context "Error Handling" {
        Describe "Resilience Tests" {
            It "Should handle missing AD module gracefully" {
                Mock Import-Module { throw "Module not found" }
                
                { Test-ADDSInstallation } | Should -Not -Throw
            }
            
            It "Should handle WMI query failures gracefully" {
                Mock Get-WmiObject { throw "WMI query failed" }
                
                { Test-DomainController } | Should -Not -Throw
            }
        }
    }
}
