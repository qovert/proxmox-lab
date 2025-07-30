# DSC v3 Domain Controller Configuration

This project contains a PowerShell DSC v3 resource for configuring two domain controllers in an Active Directory environment.

## Features

- Promotes the first server as a primary domain controller
- Promotes the second server as an additional domain controller
- Configures Active Directory Domain Services
- Sets up DNS services
- Implements proper error handling and logging
- Supports both new forest creation and domain joining

## Requirements

- PowerShell 7.x or later
- DSC v3
- Windows Server 2019 or later
- Appropriate permissions for domain controller promotion

## Usage

1. Configure the parameters in `domain-controllers.dsc.yaml`
2. Run the DSC configuration: `dsc config set domain-controllers.dsc.yaml`

## Files

- `domain-controllers.dsc.yaml` - Main DSC configuration file
- `DomainController.psm1` - PowerShell DSC resource module
- `DomainController.schema.json` - JSON schema for the resource
- `examples/` - Example configurations
- `tests/` - Unit and integration tests
