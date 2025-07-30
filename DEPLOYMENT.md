# DSC v3 Domain Controller Resource - Deployment Guide

## Prerequisites

### System Requirements

- Windows Server 2019 or later
- PowerShell 7.x or later
- DSC v3 installed
- Administrator privileges
- Network connectivity between domain controllers

### Required PowerShell Modules

- ADDSDeployment (installed with ADDS role)
- Pester (for testing) - `Install-Module Pester -Force`

## Installation

1. **Clone or download the resource**

   ```powershell
   git clone <repository-url> C:\DSCResources\DomainController
   ```

2. **Verify DSC v3 installation**

   ```powershell
   dsc --version
   ```

3. **Test the resource**

   ```powershell
   cd C:\DSCResources\DomainController
   dsc resource get --resource DomainController/DomainController
   ```

## Deployment Steps

### Step 1: Prepare Configuration

1. Copy one of the example configurations:

   ```powershell
   cp examples/simple-lab.dsc.yaml my-domain.dsc.yaml
   ```

2. Edit the configuration file with your domain details:

   ```yaml
   parameters:
     domainName:
       type: string
       default: "yourdomain.local"
     
     safeModePassword:
       type: securestring
       default: "YourSecurePassword123!"
   ```

### Step 2: Deploy Primary Domain Controller

1. **Apply the configuration to the first server:**

   ```powershell
   # On the primary DC server
   dsc config set my-domain.dsc.yaml
   ```

2. **Monitor the deployment:**

   ```powershell
   # Check Windows event logs
   Get-WinEvent -LogName "Directory Service" -MaxEvents 50
   ```

3. **Reboot when prompted:**

   ```powershell
   Restart-Computer -Force
   ```

4. **Verify primary DC after reboot:**

   ```powershell
   # Check domain controller status
   Get-ADDomainController -Server localhost
   
   # Verify FSMO roles
   Get-ADForest | Select-Object SchemaMaster, DomainNamingMaster
   Get-ADDomain | Select-Object PDCEmulator, RIDMaster, InfrastructureMaster
   ```

### Step 3: Deploy Secondary Domain Controller

1. **Wait for primary DC to be fully operational** (usually 5-10 minutes after reboot)

2. **Apply the configuration to the second server:**

   ```powershell
   # On the secondary DC server
   dsc config set my-domain.dsc.yaml
   ```

3. **Reboot when prompted:**

   ```powershell
   Restart-Computer -Force
   ```

4. **Verify both domain controllers:**

   ```powershell
   # List all domain controllers
   Get-ADDomainController -Filter *
   
   # Test replication
   repadmin /showrepl
   ```

## Post-Deployment Verification

### Health Checks

1. **Verify Active Directory replication:**

   ```powershell
   # Check replication status
   Get-ADReplicationFailure -Target (Get-ADDomainController -Filter *)
   
   # Force replication
   repadmin /syncall /AdeP
   ```

2. **Test DNS functionality:**

   ```powershell
   # Test DNS resolution
   nslookup yourdomain.local
   nslookup _ldap._tcp.yourdomain.local
   ```

3. **Verify SYSVOL replication:**

   ```powershell
   # Check SYSVOL contents
   Get-ChildItem "\\yourdomain.local\SYSVOL\yourdomain.local"
   ```

### Security Validation

1. **Review security event logs:**

   ```powershell
   Get-WinEvent -LogName Security -FilterHashtable @{ID=4624,4625} -MaxEvents 20
   ```

2. **Verify Kerberos functionality:**

   ```powershell
   # Test Kerberos tickets
   klist
   ```

3. **Check FSMO role distribution:**

   ```powershell
   netdom query fsmo
   ```

## Troubleshooting

### Common Issues

1. **Promotion fails with "Access Denied"**
   - Verify administrator privileges
   - Check domain admin credentials for secondary DC
   - Ensure time synchronization between servers

2. **DNS resolution issues**
   - Verify DNS server settings
   - Check firewall rules (ports 53, 88, 135, 389, 445, 464, 636, 3268, 3269)
   - Test network connectivity between DCs

3. **Replication failures**
   - Check network connectivity
   - Verify DNS resolution
   - Review Directory Service event logs

### Diagnostic Commands

```powershell
# Check AD services status
Get-Service ADWS, DNS, KDC, NTDS | Format-Table Name, Status

# Test AD connectivity
Test-ADServiceAccount -Identity "YOURDOMAIN\Administrator"

# Verify forest and domain functional levels
Get-ADForest | Select-Object ForestMode
Get-ADDomain | Select-Object DomainMode

# Check replication topology
repadmin /showreps
```

### Log Locations

- **Directory Service logs:** `Event Viewer > Applications and Services Logs > Directory Service`
- **DNS logs:** `Event Viewer > Applications and Services Logs > DNS Server`
- **System logs:** `Event Viewer > Windows Logs > System`
- **Security logs:** `Event Viewer > Windows Logs > Security`

## Maintenance

### Regular Tasks

1. **Monitor replication health:**

   ```powershell
   # Weekly check
   dcdiag /test:replications
   ```

2. **Backup system state:**

   ```powershell
   # Create system state backup
   wbadmin start systemstatebackup -backuptarget:D:\Backups
   ```

3. **Update DNS scavenging:**

   ```powershell
   # Configure DNS aging
   dnscmd /config /enablescavenging 1
   ```

## Security Best Practices

1. **Use complex passwords** for SafeMode and domain admin accounts
2. **Implement network segmentation** for domain controllers
3. **Enable audit logging** for critical AD events
4. **Regular security updates** and patches
5. **Monitor privileged account usage**
6. **Implement backup and disaster recovery procedures**

## Support

For issues and support:

1. Check the Windows Event Logs first
2. Review the DSC configuration syntax
3. Validate network connectivity and DNS resolution
4. Consult Microsoft documentation for AD troubleshooting
