# PQC Email System - Administrator Installation Guide

## Overview

This guide provides step-by-step instructions for installing and configuring the Post-Quantum Cryptography (PQC) email system in a financial institution environment. The system integrates with Microsoft Outlook to provide quantum-resistant encryption for sensitive email communications.

## Prerequisites

### System Requirements

**Minimum Requirements:**
- Windows Server 2016 or later / Windows 10 Pro or later
- Microsoft Outlook 2019, 2021, or Microsoft 365
- .NET 6.0 Runtime or later
- 4 GB RAM
- 2 GB free disk space
- Network connectivity for certificate discovery

**Recommended Requirements:**
- Windows Server 2019 or later / Windows 11 Pro
- Microsoft Outlook with latest updates
- .NET 8.0 Runtime
- 8 GB RAM
- 10 GB free disk space
- Hardware Security Module (HSM) support
- Active Directory integration

### Administrative Privileges

- Local Administrator rights on target machines
- Domain Administrator rights (for Group Policy deployment)
- Exchange Administrator rights (for organization-wide policies)
- Certificate Authority Administrator rights (for certificate management)

### Network Requirements

- HTTPS access to certificate authorities
- DNS resolution for SMIMEA record lookup
- Firewall rules for OCSP/CRL checking
- Optional: SIEM system connectivity for audit logging

## Installation Steps

### Step 1: Prepare Installation Environment

1. **Download Installation Package**
   ```powershell
   # Download from secure repository
   Invoke-WebRequest -Uri "https://secure-repo.company.com/pqc-email/latest/PqcEmailSetup.msi" -OutFile "PqcEmailSetup.msi"
   
   # Verify digital signature
   Get-AuthenticodeSignature .\PqcEmailSetup.msi
   ```

2. **Verify Prerequisites**
   ```powershell
   # Check .NET version
   dotnet --version
   
   # Check Outlook installation
   Get-ItemProperty HKLM:\Software\Microsoft\Office\*\Outlook\InstallRoot\
   
   # Check available disk space
   Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "C:"} | Select-Object Size,FreeSpace
   ```

3. **Create Service Account** (for automated installations)
   ```powershell
   # Create dedicated service account
   New-LocalUser -Name "PqcEmailService" -Description "PQC Email System Service Account" -NoPassword
   Add-LocalGroupMember -Group "Users" -Member "PqcEmailService"
   ```

### Step 2: Install Core Components

1. **Run Installation Package**
   ```powershell
   # Silent installation with logging
   msiexec /i PqcEmailSetup.msi /quiet /l*v "C:\Temp\PqcEmailInstall.log"
   
   # Interactive installation (for first-time setup)
   msiexec /i PqcEmailSetup.msi
   ```

2. **Verify Installation**
   ```powershell
   # Check installed files
   Get-ChildItem "C:\Program Files\PqcEmail" -Recurse
   
   # Check Windows services
   Get-Service -Name "PqcEmail*"
   
   # Check Outlook add-in registration
   Get-ChildItem "HKCU:\Software\Microsoft\Office\Outlook\Addins\PqcEmail*"
   ```

3. **Install Cryptographic Libraries**
   ```powershell
   # Install Open Quantum Safe library
   Copy-Item "libs\liboqs.dll" "C:\Program Files\PqcEmail\bin\"
   
   # Register cryptographic providers
   .\RegisterCryptoProviders.exe
   
   # Verify installation
   .\TestCryptoProviders.exe
   ```

### Step 3: Configure Certificate Management

1. **Configure Certificate Store Integration**
   ```powershell
   # Import root CA certificates
   Import-Certificate -FilePath "RootCA.cer" -CertStoreLocation "Cert:\LocalMachine\Root"
   
   # Configure certificate auto-enrollment
   Set-GPRegistryValue -Name "Certificate Auto-Enrollment" -Key "HKLM\Software\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName "AEPolicy" -Type DWord -Value 7
   ```

2. **Setup HSM Integration** (Optional)
   ```powershell
   # Install PKCS#11 driver
   .\InstallHsmDriver.exe
   
   # Configure HSM connection
   Set-Content "C:\Program Files\PqcEmail\Config\hsm-config.json" @"
   {
     "enabled": true,
     "libraryPath": "C:\\Program Files\\HSMVendor\\pkcs11.dll",
     "slotId": 0,
     "pin": "ENCRYPTED_PIN_PLACEHOLDER"
   }
   "@
   ```

3. **Generate Initial Key Pairs**
   ```powershell
   # Generate PQC key pairs
   .\PqcKeyGen.exe -algorithm ML-KEM-768 -output "user@company.com"
   .\PqcKeyGen.exe -algorithm ML-DSA-65 -output "user@company.com"
   
   # Generate classical key pairs (for hybrid mode)
   .\ClassicalKeyGen.exe -algorithm RSA-2048 -output "user@company.com"
   ```

### Step 4: Configure Policy Engine

1. **Create Policy Configuration**
   ```json
   {
     "globalCryptographic": {
       "mode": "Hybrid",
       "preferredKemAlgorithm": "ML-KEM-768",
       "preferredSignatureAlgorithm": "ML-DSA-65",
       "fallbackKemAlgorithm": "RSA-OAEP-2048",
       "fallbackSignatureAlgorithm": "RSA-PSS-2048",
       "alwaysCreateDualSignatures": true
     },
     "security": {
       "minimumRsaKeySize": 2048,
       "prohibitWeakAlgorithms": true,
       "requireHardwareProtection": false,
       "prohibitedAlgorithms": ["MD5", "SHA1", "RSA-1024", "DES", "3DES"],
       "minimumSecurityLevel": "Standard"
     },
     "audit": {
       "enableDetailedLogging": true,
       "logPolicyDecisions": true,
       "logFallbackEvents": true,
       "logSecurityViolations": true,
       "logLevel": "Information"
     }
   }
   ```

2. **Deploy via Group Policy**
   ```powershell
   # Copy policy template
   Copy-Item "GroupPolicy\PqcEmailPolicy.admx" "C:\Windows\SYSVOL\sysvol\domain.com\Policies\PolicyDefinitions\"
   Copy-Item "GroupPolicy\PqcEmailPolicy.adml" "C:\Windows\SYSVOL\sysvol\domain.com\Policies\PolicyDefinitions\en-US\"
   
   # Apply Group Policy
   gpupdate /force
   ```

### Step 5: Configure Monitoring and Logging

1. **Setup Audit Logging**
   ```powershell
   # Create audit log directory
   New-Item -ItemType Directory -Path "C:\ProgramData\PqcEmail\Logs" -Force
   
   # Set appropriate permissions
   $acl = Get-Acl "C:\ProgramData\PqcEmail\Logs"
   $acl.SetAccessRuleProtection($true, $false)
   $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
   $acl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")))
   Set-Acl "C:\ProgramData\PqcEmail\Logs" $acl
   ```

2. **Configure SIEM Integration**
   ```json
   {
     "siemIntegration": {
       "enabled": true,
       "endpoint": "https://siem.company.com/api/events",
       "apiKey": "ENCRYPTED_API_KEY",
       "batchEndpoint": "https://siem.company.com/api/batch",
       "timeoutSeconds": 30
     }
   }
   ```

3. **Setup Windows Event Log Source**
   ```powershell
   # Create custom event log source
   New-EventLog -LogName "Application" -Source "PQC Email"
   
   # Verify event log source
   Get-EventLog -LogName "Application" -Source "PQC Email" -Newest 1
   ```

### Step 6: Configure Outlook Integration

1. **Register Outlook Add-in**
   ```powershell
   # Register COM add-in
   regsvr32 "C:\Program Files\PqcEmail\Outlook\PqcEmailAddin.dll"
   
   # Verify registration
   Get-ChildItem "HKLM:\SOFTWARE\Classes\TypeLib" | Where-Object {$_.Name -like "*PqcEmail*"}
   ```

2. **Configure Add-in Settings**
   ```registry
   [HKEY_CURRENT_USER\Software\Microsoft\Office\Outlook\Addins\PqcEmail.Connect]
   "LoadBehavior"=dword:00000003
   "Description"="Post-Quantum Cryptography Email Add-in"
   "FriendlyName"="PQC Email"
   ```

3. **Deploy User Settings**
   ```json
   {
     "outlookIntegration": {
       "enableVisualIndicators": true,
       "showSecurityBadges": true,
       "requireUserConfirmation": false,
       "defaultEncryptionMode": "Auto",
       "showAdvancedOptions": false
     }
   }
   ```

## Configuration Options

### Global Configuration File

Location: `C:\Program Files\PqcEmail\Config\appsettings.json`

```json
{
  "PqcEmail": {
    "CryptographicProvider": "BouncyCastle",
    "CertificateStore": "WindowsStore",
    "PolicyEngine": "Default",
    "AuditLogging": {
      "Enabled": true,
      "LogLevel": "Information",
      "LogToFile": true,
      "LogToWindowsEventLog": true,
      "LogToSiem": true
    },
    "Performance": {
      "MaxOperationTimeMs": 2000,
      "MaxMemoryUsageMB": 100,
      "CacheExpiryMinutes": 60,
      "EnablePerformanceMonitoring": true
    },
    "Monitoring": {
      "HealthCheckIntervalMinutes": 5,
      "MetricsCollectionEnabled": true,
      "DashboardEnabled": true
    }
  }
}
```

### Registry Configuration

Key registry settings for system-wide configuration:

```registry
[HKEY_LOCAL_MACHINE\SOFTWARE\PqcEmail]
"InstallPath"="C:\\Program Files\\PqcEmail"
"Version"="1.0.0"
"ConfigPath"="C:\\Program Files\\PqcEmail\\Config"

[HKEY_LOCAL_MACHINE\SOFTWARE\PqcEmail\Cryptography]
"DefaultKemAlgorithm"="ML-KEM-768"
"DefaultSignatureAlgorithm"="ML-DSA-65"
"HybridModeEnabled"=dword:00000001

[HKEY_LOCAL_MACHINE\SOFTWARE\PqcEmail\Policies]
"ProhibitWeakAlgorithms"=dword:00000001
"RequireEncryption"=dword:00000001
"AuditAllOperations"=dword:00000001
```

## Verification and Testing

### Post-Installation Verification

1. **Test Cryptographic Operations**
   ```powershell
   # Run built-in diagnostics
   .\PqcEmail.Diagnostics.exe --test-crypto
   
   # Test key generation
   .\PqcEmail.Diagnostics.exe --test-keygen
   
   # Test encryption/decryption
   .\PqcEmail.Diagnostics.exe --test-encryption
   ```

2. **Test Outlook Integration**
   ```powershell
   # Start Outlook with verbose logging
   outlook.exe /safe /cleanviews
   
   # Check add-in load status
   Get-ItemProperty "HKCU:\Software\Microsoft\Office\Outlook\Addins\PqcEmail.Connect" -Name "LoadBehavior"
   ```

3. **Test Audit Logging**
   ```powershell
   # Generate test audit events
   .\PqcEmail.Diagnostics.exe --test-audit
   
   # Check Windows Event Log
   Get-EventLog -LogName "Application" -Source "PQC Email" -Newest 10
   
   # Check file-based audit log
   Get-Content "C:\ProgramData\PqcEmail\Logs\policy-audit.json" -Tail 10
   ```

### Health Check Commands

```powershell
# Check system health
.\PqcEmail.HealthCheck.exe --comprehensive

# Check certificate health
.\PqcEmail.HealthCheck.exe --certificates

# Check policy engine health
.\PqcEmail.HealthCheck.exe --policies

# Check performance metrics
.\PqcEmail.HealthCheck.exe --performance
```

## Troubleshooting

### Common Installation Issues

**Issue: "Failed to register cryptographic provider"**
- Solution: Run installation as Administrator
- Verify: Check Windows event log for detailed error messages
- Action: Re-run `RegisterCryptoProviders.exe` manually

**Issue: "Outlook add-in not loading"**
- Solution: Check Outlook security settings and trust center
- Verify: Ensure add-in is not blocked by group policy
- Action: Reset Outlook profile and re-register add-in

**Issue: "Certificate enrollment fails"**
- Solution: Verify Active Directory certificate services configuration
- Verify: Check network connectivity to certificate authority
- Action: Manually request certificates using certificate snap-in

### Log File Locations

- Installation logs: `%TEMP%\PqcEmailInstall.log`
- Application logs: `C:\ProgramData\PqcEmail\Logs\application.log`
- Audit logs: `C:\ProgramData\PqcEmail\Logs\policy-audit.json`
- Performance logs: `C:\ProgramData\PqcEmail\Logs\metrics.log`
- Windows Event Log: Application log, source "PQC Email"

### Support Contacts

- Technical Support: pqc-support@company.com
- Security Team: security@company.com
- IT Service Desk: servicedesk@company.com
- Emergency Contact: +1-555-PQC-HELP

## Security Considerations

### Hardening Recommendations

1. **File System Permissions**
   - Restrict access to configuration files
   - Protect private key storage locations
   - Enable file system auditing

2. **Network Security**
   - Use TLS for all external communications
   - Implement certificate pinning for critical connections
   - Monitor for unusual network activity

3. **Access Control**
   - Implement role-based access control
   - Regular access reviews
   - Multi-factor authentication for administrative functions

4. **Monitoring**
   - Enable comprehensive audit logging
   - Set up alerting for security events
   - Regular security assessments

### Compliance Requirements

- **SOX**: Maintain detailed audit trails for all financial communications
- **GDPR**: Ensure proper data protection and privacy controls
- **FFIEC**: Implement cybersecurity risk management practices
- **Industry Standards**: Follow NIST, ISO 27001 guidelines

## Maintenance and Updates

### Regular Maintenance Tasks

1. **Certificate Management**
   - Monitor certificate expiration dates
   - Renew certificates before expiration
   - Verify certificate chain integrity

2. **Key Rotation**
   - Schedule regular key rotation
   - Update key escrow systems
   - Verify key backup procedures

3. **Software Updates**
   - Install security updates promptly
   - Test updates in development environment
   - Maintain rollback procedures

4. **Performance Monitoring**
   - Review performance metrics regularly
   - Optimize system configuration
   - Plan capacity upgrades

### Update Procedures

```powershell
# Check for updates
.\PqcEmail.Update.exe --check

# Download updates
.\PqcEmail.Update.exe --download

# Install updates (requires restart)
.\PqcEmail.Update.exe --install

# Verify update installation
.\PqcEmail.Diagnostics.exe --version
```

---

*This installation guide is part of the PQC Email System documentation suite. For additional information, refer to the User Guide, API Documentation, and Operational Runbooks.*