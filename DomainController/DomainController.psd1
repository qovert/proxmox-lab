@{
    # Module manifest for DomainController DSC v3 resource
    RootModule = 'DomainController.ps1'
    ModuleVersion = '1.0.0'
    GUID = 'a1b2c3d4-e5f6-7890-abcd-ef1234567890'
    Author = 'DSC Administrator'
    CompanyName = 'Organization'
    Copyright = '(c) 2025. All rights reserved.'
    Description = 'DSC v3 resource for configuring Active Directory Domain Controllers'
    
    # Minimum PowerShell version
    PowerShellVersion = '7.0'
    
    # Operating system requirements
    CompatiblePSEditions = @('Core')
    
    # Required modules
    RequiredModules = @(
        @{
            ModuleName = 'ADDSDeployment'
            ModuleVersion = '1.0.0.0'
        }
    )
    
    # Functions to export
    FunctionsToExport = @(
        'Get-DomainControllerConfiguration',
        'Set-DomainControllerConfiguration',
        'Test-DomainControllerConfiguration'
    )
    
    # Variables to export
    VariablesToExport = @()
    
    # Aliases to export
    AliasesToExport = @()
    
    # Private data
    PrivateData = @{
        PSData = @{
            # Tags for module discovery
            Tags = @('DSC', 'DomainController', 'ActiveDirectory', 'Windows', 'Infrastructure')
            
            # License URI
            LicenseUri = ''
            
            # Project URI
            ProjectUri = ''
            
            # Icon URI
            IconUri = ''
            
            # Release notes
            ReleaseNotes = @'
Version 1.0.0
- Initial release
- Support for primary domain controller promotion (new forest)
- Support for additional domain controller promotion
- Comprehensive error handling and logging
- Security best practices implementation
- Support for custom AD database, log, and SYSVOL paths
'@
        }
    }
}
