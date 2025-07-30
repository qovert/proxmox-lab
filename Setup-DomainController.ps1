#!/usr/bin/env pwsh

<#
.SYNOPSIS
    Setup and validation script for the DSC v3 Domain Controller resource
.DESCRIPTION
    This script helps set up, validate, and test the Domain Controller DSC v3 resource
.PARAMETER Action
    The action to perform: Setup, Validate, Test, or Deploy
.PARAMETER ConfigFile
    Path to the DSC configuration file
.EXAMPLE
    ./Setup-DomainController.ps1 -Action Setup
    ./Setup-DomainController.ps1 -Action Validate -ConfigFile "domain-controllers.dsc.yaml"
#>

param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Setup', 'Validate', 'Test', 'Deploy')]
    [string]$Action,
    
    [Parameter()]
    [string]$ConfigFile = "domain-controllers.dsc.yaml",
    
    [Parameter()]
    [switch]$Force
)

#region Helper Functions

function Write-StatusMessage {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Error')]
        [string]$Type = 'Info'
    )
    
    $colors = @{
        'Info' = 'Cyan'
        'Success' = 'Green'
        'Warning' = 'Yellow'
        'Error' = 'Red'
    }
    
    $timestamp = Get-Date -Format 'HH:mm:ss'
    Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
    Write-Host $Message -ForegroundColor $colors[$Type]
}

function Test-Prerequisites {
    Write-StatusMessage "Checking prerequisites..." -Type Info
    
    $issues = @()
    
    # Check PowerShell version
    if ($PSVersionTable.PSVersion.Major -lt 7) {
        $issues += "PowerShell 7.x or later is required. Current version: $($PSVersionTable.PSVersion)"
    }
    
    # Check if running on Windows
    if (-not $IsWindows) {
        $issues += "This resource requires Windows Server"
    }
    
    # Check if running as administrator
    if ($IsWindows) {
        $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
        if (-not $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
            $issues += "Administrator privileges required"
        }
    }
    
    # Check DSC v3
    try {
        $dscVersion = dsc --version 2>$null
        if (-not $dscVersion) {
            $issues += "DSC v3 is not installed or not in PATH"
        }
        else {
            Write-StatusMessage "DSC version: $dscVersion" -Type Success
        }
    }
    catch {
        $issues += "DSC v3 is not installed or not in PATH"
    }
    
    if ($issues.Count -gt 0) {
        Write-StatusMessage "Prerequisites check failed:" -Type Error
        $issues | ForEach-Object { Write-StatusMessage "  - $_" -Type Error }
        return $false
    }
    
    Write-StatusMessage "Prerequisites check passed" -Type Success
    return $true
}

function Install-RequiredModules {
    Write-StatusMessage "Installing required PowerShell modules..." -Type Info
    
    $modules = @('ADDSDeployment', 'Pester')
    
    foreach ($module in $modules) {
        try {
            if (-not (Get-Module -ListAvailable -Name $module)) {
                Write-StatusMessage "Installing module: $module" -Type Info
                Install-Module -Name $module -Force -Scope CurrentUser
            }
            else {
                Write-StatusMessage "Module already installed: $module" -Type Success
            }
        }
        catch {
            Write-StatusMessage "Failed to install module $module`: $($_.Exception.Message)" -Type Error
        }
    }
}

function Test-ResourceManifest {
    Write-StatusMessage "Validating resource manifest..." -Type Info
    
    $manifestPath = Join-Path $PSScriptRoot "DomainController" "DomainController.dsc.resource.json"
    
    if (-not (Test-Path $manifestPath)) {
        Write-StatusMessage "Resource manifest not found: $manifestPath" -Type Error
        return $false
    }
    
    try {
        $manifest = Get-Content $manifestPath | ConvertFrom-Json
        
        $requiredProperties = @('type', 'version', 'get', 'set', 'test', 'schema')
        foreach ($prop in $requiredProperties) {
            if (-not $manifest.PSObject.Properties[$prop]) {
                Write-StatusMessage "Missing required property in manifest: $prop" -Type Error
                return $false
            }
        }
        
        Write-StatusMessage "Resource manifest is valid" -Type Success
        return $true
    }
    catch {
        Write-StatusMessage "Invalid JSON in resource manifest: $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Test-ResourceScript {
    Write-StatusMessage "Validating resource script..." -Type Info
    
    $scriptPath = Join-Path $PSScriptRoot "DomainController" "DomainController.ps1"
    
    if (-not (Test-Path $scriptPath)) {
        Write-StatusMessage "Resource script not found: $scriptPath" -Type Error
        return $false
    }
    
    try {
        # Test script syntax
        $null = [System.Management.Automation.PSParser]::Tokenize((Get-Content $scriptPath -Raw), [ref]$null)
        Write-StatusMessage "Resource script syntax is valid" -Type Success
        return $true
    }
    catch {
        Write-StatusMessage "Script syntax error: $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Test-DSCConfiguration {
    param([string]$ConfigPath)
    
    Write-StatusMessage "Validating DSC configuration..." -Type Info
    
    if (-not (Test-Path $ConfigPath)) {
        Write-StatusMessage "Configuration file not found: $ConfigPath" -Type Error
        return $false
    }
    
    try {
        # Basic YAML syntax validation
        $content = Get-Content $ConfigPath -Raw
        
        # Check for required sections
        $requiredSections = @('metadata', 'parameters', 'resources')
        foreach ($section in $requiredSections) {
            if ($content -notmatch "^$section\s*:") {
                Write-StatusMessage "Missing required section in configuration: $section" -Type Warning
            }
        }
        
        # Check for DomainController resource type
        if ($content -notmatch "type:\s+DomainController/DomainController") {
            Write-StatusMessage "DomainController resource type not found in configuration" -Type Error
            return $false
        }
        
        Write-StatusMessage "DSC configuration appears valid" -Type Success
        return $true
    }
    catch {
        Write-StatusMessage "Configuration validation error: $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Invoke-UnitTests {
    Write-StatusMessage "Running unit tests..." -Type Info
    
    $testPath = Join-Path $PSScriptRoot "tests" "DomainController.Tests.ps1"
    
    if (-not (Test-Path $testPath)) {
        Write-StatusMessage "Unit tests not found: $testPath" -Type Warning
        return $true
    }
    
    try {
        $testResults = Invoke-Pester -Path $testPath -PassThru
        
        if ($testResults.FailedCount -eq 0) {
            Write-StatusMessage "All unit tests passed ($($testResults.PassedCount) tests)" -Type Success
            return $true
        }
        else {
            Write-StatusMessage "Unit tests failed: $($testResults.FailedCount) failed, $($testResults.PassedCount) passed" -Type Error
            return $false
        }
    }
    catch {
        Write-StatusMessage "Error running unit tests: $($_.Exception.Message)" -Type Error
        return $false
    }
}

function Deploy-Configuration {
    param([string]$ConfigPath)
    
    Write-StatusMessage "Deploying DSC configuration..." -Type Info
    
    if (-not (Test-Path $ConfigPath)) {
        Write-StatusMessage "Configuration file not found: $ConfigPath" -Type Error
        return $false
    }
    
    try {
        # Test the configuration first
        Write-StatusMessage "Testing configuration with DSC..." -Type Info
        $testOutput = dsc config test $ConfigPath 2>&1
        
        if ($LASTEXITCODE -ne 0) {
            Write-StatusMessage "DSC configuration test failed:" -Type Error
            $testOutput | ForEach-Object { Write-StatusMessage "  $_" -Type Error }
            return $false
        }
        
        # Apply the configuration
        if ($Force -or (Read-Host "Apply configuration? (y/N)") -eq 'y') {
            Write-StatusMessage "Applying DSC configuration..." -Type Info
            $setOutput = dsc config set $ConfigPath 2>&1
            
            if ($LASTEXITCODE -eq 0) {
                Write-StatusMessage "DSC configuration applied successfully" -Type Success
                Write-StatusMessage "Note: A reboot may be required to complete domain controller promotion" -Type Warning
                return $true
            }
            else {
                Write-StatusMessage "DSC configuration failed:" -Type Error
                $setOutput | ForEach-Object { Write-StatusMessage "  $_" -Type Error }
                return $false
            }
        }
        else {
            Write-StatusMessage "Deployment cancelled by user" -Type Info
            return $false
        }
    }
    catch {
        Write-StatusMessage "Deployment error: $($_.Exception.Message)" -Type Error
        return $false
    }
}

#endregion

#region Main Logic

Write-StatusMessage "DSC v3 Domain Controller Resource - $Action" -Type Info
Write-StatusMessage "Working directory: $PSScriptRoot" -Type Info

$success = $true

switch ($Action) {
    'Setup' {
        $success = Test-Prerequisites
        if ($success) {
            Install-RequiredModules
        }
    }
    
    'Validate' {
        $success = Test-Prerequisites -and 
                   Test-ResourceManifest -and 
                   Test-ResourceScript -and 
                   Test-DSCConfiguration -ConfigPath $ConfigFile
    }
    
    'Test' {
        $success = Test-Prerequisites -and 
                   Test-ResourceManifest -and 
                   Test-ResourceScript -and 
                   Invoke-UnitTests
    }
    
    'Deploy' {
        $success = Test-Prerequisites -and 
                   Test-ResourceManifest -and 
                   Test-ResourceScript -and 
                   Test-DSCConfiguration -ConfigPath $ConfigFile -and
                   Deploy-Configuration -ConfigPath $ConfigFile
    }
}

if ($success) {
    Write-StatusMessage "$Action completed successfully" -Type Success
    exit 0
}
else {
    Write-StatusMessage "$Action failed" -Type Error
    exit 1
}

#endregion
