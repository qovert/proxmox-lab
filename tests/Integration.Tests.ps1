#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Integration tests for the Domain Controller DSC v3 resource
.DESCRIPTION
    These tests validate the resource against actual Windows Server environments
    WARNING: These tests will modify system configuration and should only be run in test environments
#>

Describe "DomainController Integration Tests" -Tag "Integration" {
    BeforeAll {
        # Ensure we're running on Windows Server
        $osInfo = Get-CimInstance -ClassName Win32_OperatingSystem
        if ($osInfo.ProductType -ne 2 -and $osInfo.ProductType -ne 3) {
            throw "Integration tests must be run on Windows Server"
        }
        
        # Set test parameters
        $script:TestDomainName = "integration.test"
        $script:TestNetBIOSName = "INTTEST"
        $script:TestPassword = "IntegrationTest123!"
        $script:ResourcePath = Join-Path $PSScriptRoot ".." "DomainController"
        
        Write-Warning "Integration tests will modify system configuration. Continue only in test environments."
    }
    
    Context "Resource Manifest Validation" {
        It "Should have valid resource manifest" {
            $manifestPath = Join-Path $script:ResourcePath "DomainController.dsc.resource.json"
            $manifestPath | Should -Exist
            
            $manifest = Get-Content $manifestPath | ConvertFrom-Json
            $manifest.type | Should -Be "DomainController/DomainController"
            $manifest.version | Should -Match "^\d+\.\d+\.\d+$"
        }
        
        It "Should have executable PowerShell script" {
            $scriptPath = Join-Path $script:ResourcePath "DomainController.ps1"
            $scriptPath | Should -Exist
            
            # Test script syntax
            $errors = $null
            [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$errors)
            $errors | Should -BeNullOrEmpty
        }
    }
    
    Context "ADDS Feature Management" {
        It "Should detect ADDS installation status" {
            $feature = Get-WindowsFeature -Name AD-Domain-Services
            $feature | Should -Not -BeNullOrEmpty
            $feature.Name | Should -Be "AD-Domain-Services"
        }
        
        It "Should install ADDS feature if not present" -Skip {
            # This test is skipped by default as it modifies system state
            # Remove -Skip to run in dedicated test environment
            
            $feature = Get-WindowsFeature -Name AD-Domain-Services
            if ($feature.InstallState -eq "Installed") {
                Set-ItResult -Skipped -Because "ADDS already installed"
                return
            }
            
            Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools
            $installedFeature = Get-WindowsFeature -Name AD-Domain-Services
            $installedFeature.InstallState | Should -Be "Installed"
        }
    }
    
    Context "DSC Resource Operations" {
        It "Should execute 'get' operation without errors" {
            $scriptPath = Join-Path $script:ResourcePath "DomainController.ps1"
            
            { & pwsh -NoProfile -NonInteractive -File $scriptPath "get" } | Should -Not -Throw
        }
        
        It "Should execute 'test' operation with valid input" {
            $scriptPath = Join-Path $script:ResourcePath "DomainController.ps1"
            
            $testInput = @{
                ServerName = $env:COMPUTERNAME
                DomainName = $script:TestDomainName
                SafeModeAdministratorPassword = $script:TestPassword
                Role = "PrimaryDomainController"
            } | ConvertTo-Json
            
            { $testInput | & pwsh -NoProfile -NonInteractive -File $scriptPath "test" } | Should -Not -Throw
        }
    }
    
    Context "Domain Controller Promotion" -Skip {
        # These tests are skipped by default as they perform actual DC promotion
        # Remove -Skip and run only in isolated test environments
        
        It "Should promote server to primary domain controller" {
            $scriptPath = Join-Path $script:ResourcePath "DomainController.ps1"
            
            $setInput = @{
                ServerName = $env:COMPUTERNAME
                DomainName = $script:TestDomainName
                NetBIOSName = $script:TestNetBIOSName
                SafeModeAdministratorPassword = $script:TestPassword
                Role = "PrimaryDomainController"
                CreateNewForest = $true
                ForestMode = "WinThreshold"
                DomainMode = "WinThreshold"
                InstallDNS = $true
            } | ConvertTo-Json
            
            $result = $setInput | & pwsh -NoProfile -NonInteractive -File $scriptPath "set" | ConvertFrom-Json
            $result.Status | Should -Be "Success"
            $result.RebootRequired | Should -Be $true
        }
        
        It "Should verify domain controller configuration after promotion" {
            # This test would run after reboot in a real scenario
            Start-Sleep -Seconds 30  # Allow for AD services to start
            
            $domainRole = (Get-WmiObject -Class Win32_ComputerSystem).DomainRole
            $domainRole | Should -BeIn @(4, 5)  # Backup or Primary DC
            
            $domain = Get-ADDomain -Current LocalComputer
            $domain.DNSRoot | Should -Be $script:TestDomainName
        }
    }
    
    Context "Configuration Validation" {
        It "Should validate DSC configuration files" {
            $configPath = Join-Path $PSScriptRoot ".." "domain-controllers.dsc.yaml"
            $configPath | Should -Exist
            
            $config = Get-Content $configPath -Raw
            $config | Should -Match "type:\s+DomainController/DomainController"
        }
        
        It "Should validate example configurations" {
            $examplesPath = Join-Path $PSScriptRoot ".." "examples"
            $examples = Get-ChildItem $examplesPath -Filter "*.dsc.yaml"
            
            $examples | Should -Not -BeNullOrEmpty
            
            foreach ($example in $examples) {
                $content = Get-Content $example.FullName -Raw
                $content | Should -Match "type:\s+DomainController/DomainController"
                $content | Should -Match "ServerName:"
                $content | Should -Match "DomainName:"
            }
        }
    }
    
    AfterAll {
        Write-Warning "If domain controller promotion tests were run, a system reboot is required"
    }
}
