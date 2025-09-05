using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Certificates
{
    /// <summary>
    /// Windows Certificate Store implementation for certificate management with PQC support
    /// </summary>
    public class WindowsCertificateManager : ICertificateManager
    {
        private readonly ILogger<WindowsCertificateManager> _logger;
        private readonly Dictionary<string, CertificateInfo> _certificateCache;
        private readonly object _cacheLock = new object();

        public WindowsCertificateManager(ILogger<WindowsCertificateManager> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _certificateCache = new Dictionary<string, CertificateInfo>();
        }

        /// <summary>
        /// Discovers certificates for a specific email address across all accessible stores
        /// </summary>
        public async Task<IEnumerable<CertificateInfo>> DiscoverCertificatesAsync(string emailAddress, StoreName? storeName = null)
        {
            _logger.LogDebug("Discovering certificates for email address: {EmailAddress}", emailAddress);

            var results = new List<CertificateInfo>();
            var storeNamesToSearch = storeName.HasValue 
                ? new[] { storeName.Value }
                : new[] { StoreName.My, StoreName.AddressBook, StoreName.TrustedPeople };

            var storeLocationsToSearch = new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine };

            foreach (var location in storeLocationsToSearch)
            {
                foreach (var store in storeNamesToSearch)
                {
                    try
                    {
                        var certificates = await SearchCertificateStoreAsync(emailAddress, store, location);
                        results.AddRange(certificates);
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to search certificate store {Store} at {Location}", store, location);
                    }
                }
            }

            // Remove duplicates based on thumbprint
            var uniqueCertificates = results
                .GroupBy(c => c.Thumbprint)
                .Select(g => g.First())
                .ToList();

            _logger.LogInformation("Discovered {Count} unique certificates for {EmailAddress}", uniqueCertificates.Count, emailAddress);
            return uniqueCertificates;
        }

        /// <summary>
        /// Validates a certificate chain including PQC and classical certificates
        /// </summary>
        public async Task<CertificateValidationResult> ValidateCertificateChainAsync(X509Certificate2 certificate, X509ChainPolicy? chainPolicy = null)
        {
            _logger.LogDebug("Validating certificate chain for certificate: {Thumbprint}", certificate.Thumbprint);

            try
            {
                using var chain = new X509Chain();
                
                // Configure chain policy
                if (chainPolicy != null)
                {
                    chain.ChainPolicy = chainPolicy;
                }
                else
                {
                    // Default policy with revocation checking
                    chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                    chain.ChainPolicy.RevocationFlag = X509RevocationFlag.ExcludeRoot;
                    chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
                    chain.ChainPolicy.VerificationTime = DateTime.Now;
                }

                // Add application policy for email protection
                chain.ChainPolicy.ApplicationPolicy.Add(new Oid("1.3.6.1.5.5.7.3.4")); // Email protection

                // Build the chain
                bool chainIsValid = chain.Build(certificate);

                var result = new CertificateValidationResult
                {
                    IsValid = chainIsValid && chain.ChainStatus.Length == 0,
                    ChainElements = chain.ChainElements.Cast<X509ChainElement>().ToList()
                };

                // Analyze chain status
                if (chain.ChainStatus.Length > 0)
                {
                    foreach (var status in chain.ChainStatus)
                    {
                        result.ChainErrors.Add(status.Status);
                        result.ErrorMessages.Add($"{status.Status}: {status.StatusInformation}");

                        // Determine overall status based on errors
                        result.Status = DetermineValidationStatus(status.Status, result.Status);
                    }
                }
                else
                {
                    result.Status = CertificateValidationStatus.Valid;
                }

                // Check for PQC algorithms
                await AnalyzePqcAlgorithmsAsync(certificate, result);

                // Perform revocation checking
                result.RevocationStatus = await CheckRevocationStatusAsync(certificate);
                result.RevocationChecked = result.RevocationStatus != Models.RevocationStatus.NotChecked;

                if (result.RevocationStatus == Models.RevocationStatus.Revoked)
                {
                    result.IsValid = false;
                    result.Status = CertificateValidationStatus.Revoked;
                    result.ErrorMessages.Add("Certificate has been revoked");
                }

                // Extract trust root
                if (chain.ChainElements.Count > 0)
                {
                    result.TrustRoot = chain.ChainElements[chain.ChainElements.Count - 1].Certificate;
                }

                _logger.LogDebug("Certificate validation completed. Valid: {IsValid}, Status: {Status}", 
                    result.IsValid, result.Status);

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error validating certificate chain for certificate: {Thumbprint}", certificate.Thumbprint);
                return CertificateValidationResult.Failed($"Chain validation failed: {ex.Message}");
            }
        }

        /// <summary>
        /// Installs a certificate to the appropriate Windows Certificate Store
        /// </summary>
        public async Task<CertificateInstallationResult> InstallCertificateAsync(X509Certificate2 certificate, StoreName storeName, StoreLocation storeLocation)
        {
            _logger.LogDebug("Installing certificate {Thumbprint} to {Store} at {Location}", 
                certificate.Thumbprint, storeName, storeLocation);

            try
            {
                using var store = new X509Store(storeName, storeLocation);
                
                // Check if we can open the store with write access
                try
                {
                    store.Open(OpenFlags.ReadWrite);
                }
                catch (CryptographicException ex) when (ex.Message.Contains("access") || ex.Message.Contains("denied"))
                {
                    _logger.LogError(ex, "Access denied to certificate store {Store} at {Location}", storeName, storeLocation);
                    return CertificateInstallationResult.Failed(InstallationStatus.AccessDenied, 
                        "Access denied to certificate store. Run as administrator or check permissions.");
                }

                // Check if certificate already exists
                var existing = store.Certificates.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, false);
                if (existing.Count > 0)
                {
                    _logger.LogInformation("Certificate {Thumbprint} already exists in store", certificate.Thumbprint);
                    return CertificateInstallationResult.Failed(InstallationStatus.AlreadyExists, 
                        "Certificate already exists in the specified store");
                }

                // Validate certificate before installation
                if (!IsCertificateValid(certificate))
                {
                    return CertificateInstallationResult.Failed(InstallationStatus.InvalidCertificate, 
                        "Certificate is not valid for installation");
                }

                // Add certificate to store
                store.Add(certificate);
                
                // Verify installation
                var verification = store.Certificates.Find(X509FindType.FindByThumbprint, certificate.Thumbprint, false);
                if (verification.Count == 0)
                {
                    return CertificateInstallationResult.Failed(InstallationStatus.Failed, 
                        "Certificate installation verification failed");
                }

                _logger.LogInformation("Successfully installed certificate {Thumbprint} to {Store} at {Location}", 
                    certificate.Thumbprint, storeName, storeLocation);

                return CertificateInstallationResult.Success(certificate.Thumbprint, storeLocation, storeName);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to install certificate {Thumbprint} to {Store} at {Location}", 
                    certificate.Thumbprint, storeName, storeLocation);
                return CertificateInstallationResult.Failed(InstallationStatus.Failed, 
                    $"Installation failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Removes a certificate from Windows Certificate Store
        /// </summary>
        public async Task<bool> RemoveCertificateAsync(string thumbprint, StoreName storeName, StoreLocation storeLocation)
        {
            _logger.LogDebug("Removing certificate {Thumbprint} from {Store} at {Location}", thumbprint, storeName, storeLocation);

            try
            {
                using var store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadWrite);

                var certificates = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false);
                if (certificates.Count == 0)
                {
                    _logger.LogWarning("Certificate {Thumbprint} not found in store {Store} at {Location}", 
                        thumbprint, storeName, storeLocation);
                    return false;
                }

                foreach (X509Certificate2 cert in certificates)
                {
                    store.Remove(cert);
                    cert.Dispose();
                }

                // Clear from cache
                lock (_cacheLock)
                {
                    _certificateCache.Remove(thumbprint);
                }

                _logger.LogInformation("Successfully removed certificate {Thumbprint} from {Store} at {Location}", 
                    thumbprint, storeName, storeLocation);

                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to remove certificate {Thumbprint} from {Store} at {Location}", 
                    thumbprint, storeName, storeLocation);
                return false;
            }
        }

        /// <summary>
        /// Gets all certificates nearing expiration
        /// </summary>
        public async Task<IEnumerable<CertificateInfo>> GetExpiringCertificatesAsync(int warningDays = 30)
        {
            _logger.LogDebug("Searching for certificates expiring within {Days} days", warningDays);

            var results = new List<CertificateInfo>();
            var cutoffDate = DateTime.Now.AddDays(warningDays);

            var storeNamesToSearch = new[] { StoreName.My, StoreName.AddressBook, StoreName.TrustedPeople };
            var storeLocationsToSearch = new[] { StoreLocation.CurrentUser, StoreLocation.LocalMachine };

            foreach (var location in storeLocationsToSearch)
            {
                foreach (var storeName in storeNamesToSearch)
                {
                    try
                    {
                        using var store = new X509Store(storeName, location);
                        store.Open(OpenFlags.ReadOnly);

                        foreach (X509Certificate2 cert in store.Certificates)
                        {
                            if (cert.NotAfter <= cutoffDate)
                            {
                                var certInfo = await CreateCertificateInfoAsync(cert, storeName, location);
                                results.Add(certInfo);
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to search for expiring certificates in {Store} at {Location}", 
                            storeName, location);
                    }
                }
            }

            var uniqueResults = results
                .GroupBy(c => c.Thumbprint)
                .Select(g => g.First())
                .OrderBy(c => c.NotAfter)
                .ToList();

            _logger.LogInformation("Found {Count} certificates expiring within {Days} days", uniqueResults.Count, warningDays);
            return uniqueResults;
        }

        /// <summary>
        /// Checks certificate revocation status using OCSP and CRL
        /// </summary>
        public async Task<Models.RevocationStatus> CheckRevocationStatusAsync(X509Certificate2 certificate)
        {
            _logger.LogDebug("Checking revocation status for certificate: {Thumbprint}", certificate.Thumbprint);

            try
            {
                // Use X509Chain to check revocation status
                using var chain = new X509Chain();
                chain.ChainPolicy.RevocationMode = X509RevocationMode.Online;
                chain.ChainPolicy.RevocationFlag = X509RevocationFlag.EntireChain;
                chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

                bool chainBuilt = chain.Build(certificate);

                // Check for revocation errors
                foreach (var status in chain.ChainStatus)
                {
                    if (status.Status.HasFlag(X509ChainStatusFlags.Revoked))
                    {
                        _logger.LogWarning("Certificate {Thumbprint} is revoked", certificate.Thumbprint);
                        return Models.RevocationStatus.Revoked;
                    }
                    else if (status.Status.HasFlag(X509ChainStatusFlags.RevocationStatusUnknown) ||
                            status.Status.HasFlag(X509ChainStatusFlags.OfflineRevocation))
                    {
                        _logger.LogWarning("Revocation status unknown for certificate {Thumbprint}: {Status}", 
                            certificate.Thumbprint, status.Status);
                        return Models.RevocationStatus.Unknown;
                    }
                }

                _logger.LogDebug("Certificate {Thumbprint} is not revoked", certificate.Thumbprint);
                return Models.RevocationStatus.NotRevoked;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error checking revocation status for certificate {Thumbprint}", certificate.Thumbprint);
                return Models.RevocationStatus.Error;
            }
        }

        /// <summary>
        /// Finds the best certificate for a given email address and operation type
        /// </summary>
        public async Task<X509Certificate2?> FindBestCertificateAsync(string emailAddress, CertificateUsage operationType)
        {
            _logger.LogDebug("Finding best certificate for {EmailAddress} and usage {Usage}", emailAddress, operationType);

            var certificates = await DiscoverCertificatesAsync(emailAddress);
            var validCertificates = certificates
                .Where(c => c.IsCurrentlyValid && c.SupportsUsage(operationType))
                .OrderByDescending(c => c.IsPqcCertificate) // Prefer PQC certificates
                .ThenByDescending(c => c.NotAfter) // Then by expiration date
                .ThenByDescending(c => c.HasPrivateKey) // Prefer certificates with private keys
                .ToList();

            var bestCertificate = validCertificates.FirstOrDefault();
            if (bestCertificate != null)
            {
                _logger.LogInformation("Selected certificate {Thumbprint} for {EmailAddress} and usage {Usage}", 
                    bestCertificate.Thumbprint, emailAddress, operationType);
                return bestCertificate.Certificate;
            }

            _logger.LogWarning("No suitable certificate found for {EmailAddress} and usage {Usage}", emailAddress, operationType);
            return null;
        }

        /// <summary>
        /// Backs up certificates and private keys to encrypted storage
        /// </summary>
        public async Task<CertificateBackupResult> BackupCertificatesAsync(IEnumerable<X509Certificate2> certificates, string backupPath, string password)
        {
            _logger.LogDebug("Backing up {Count} certificates to {BackupPath}", certificates.Count(), backupPath);

            try
            {
                var certificateCollection = new X509Certificate2Collection();
                int certificateCount = 0;

                foreach (var cert in certificates)
                {
                    // Only backup certificates with private keys for meaningful backup
                    if (cert.HasPrivateKey)
                    {
                        certificateCollection.Add(cert);
                        certificateCount++;
                    }
                }

                if (certificateCount == 0)
                {
                    return CertificateBackupResult.Failed("No certificates with private keys found to backup");
                }

                // Export to PKCS#12 format with password protection
                var backupData = certificateCollection.Export(X509ContentType.Pkcs12, password);
                
                // Write to file
                await System.IO.File.WriteAllBytesAsync(backupPath, backupData);

                // Calculate file hash for integrity verification
                using var sha256 = SHA256.Create();
                var fileData = await System.IO.File.ReadAllBytesAsync(backupPath);
                var hash = sha256.ComputeHash(fileData);
                var hashString = Convert.ToHexString(hash);

                _logger.LogInformation("Successfully backed up {Count} certificates to {BackupPath}", 
                    certificateCount, backupPath);

                return CertificateBackupResult.Success(backupPath, BackupFormat.Pkcs12, certificateCount, fileData.Length, hashString);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to backup certificates to {BackupPath}", backupPath);
                return CertificateBackupResult.Failed($"Backup failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Restores certificates from encrypted backup
        /// </summary>
        public async Task<CertificateRestoreResult> RestoreCertificatesAsync(string backupPath, string password)
        {
            _logger.LogDebug("Restoring certificates from backup: {BackupPath}", backupPath);

            try
            {
                if (!System.IO.File.Exists(backupPath))
                {
                    return CertificateRestoreResult.Failed($"Backup file not found: {backupPath}");
                }

                var backupData = await System.IO.File.ReadAllBytesAsync(backupPath);
                var certificateCollection = new X509Certificate2Collection();
                
                // Import PKCS#12 data
                certificateCollection.Import(backupData, password, X509KeyStorageFlags.PersistKeySet);

                var restoredCertificates = new List<string>();
                var failedCertificates = new List<string>();

                // Install each certificate
                foreach (X509Certificate2 cert in certificateCollection)
                {
                    try
                    {
                        var installResult = await InstallCertificateAsync(cert, StoreName.My, StoreLocation.CurrentUser);
                        if (installResult.Success)
                        {
                            restoredCertificates.Add(cert.Thumbprint);
                        }
                        else
                        {
                            failedCertificates.Add($"{cert.Thumbprint}: {installResult.ErrorMessage}");
                        }
                    }
                    catch (Exception ex)
                    {
                        failedCertificates.Add($"{cert.Thumbprint}: {ex.Message}");
                    }
                }

                _logger.LogInformation("Restored {Restored} certificates, {Failed} failed from backup", 
                    restoredCertificates.Count, failedCertificates.Count);

                if (restoredCertificates.Count > 0 && failedCertificates.Count > 0)
                {
                    return CertificateRestoreResult.Partial(restoredCertificates, failedCertificates);
                }
                else if (restoredCertificates.Count > 0)
                {
                    return CertificateRestoreResult.Success(restoredCertificates);
                }
                else
                {
                    return CertificateRestoreResult.Failed("No certificates were successfully restored");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to restore certificates from backup: {BackupPath}", backupPath);
                return CertificateRestoreResult.Failed($"Restore failed: {ex.Message}", ex);
            }
        }

        #region Private Helper Methods

        private async Task<List<CertificateInfo>> SearchCertificateStoreAsync(string emailAddress, StoreName storeName, StoreLocation storeLocation)
        {
            var results = new List<CertificateInfo>();

            try
            {
                using var store = new X509Store(storeName, storeLocation);
                store.Open(OpenFlags.ReadOnly);

                // Search by subject email
                var subjectCertificates = store.Certificates.Find(X509FindType.FindBySubjectName, emailAddress, false);
                
                // Search by extension (SAN)
                var allCertificates = store.Certificates.Cast<X509Certificate2>();
                var sanCertificates = allCertificates.Where(cert => HasEmailInSan(cert, emailAddress));

                // Combine results
                var combinedCertificates = subjectCertificates.Cast<X509Certificate2>()
                    .Union(sanCertificates)
                    .Distinct();

                foreach (var cert in combinedCertificates)
                {
                    var certInfo = await CreateCertificateInfoAsync(cert, storeName, storeLocation);
                    results.Add(certInfo);
                }
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Error searching certificate store {Store} at {Location} for {EmailAddress}", 
                    storeName, storeLocation, emailAddress);
            }

            return results;
        }

        private async Task<CertificateInfo> CreateCertificateInfoAsync(X509Certificate2 certificate, StoreName storeName, StoreLocation storeLocation)
        {
            var certInfo = new CertificateInfo
            {
                Certificate = certificate,
                StoreName = storeName,
                StoreLocation = storeLocation
            };

            // Extract key usage
            var keyUsageExt = certificate.Extensions.OfType<X509KeyUsageExtension>().FirstOrDefault();
            if (keyUsageExt != null)
            {
                certInfo.KeyUsage = keyUsageExt.KeyUsages;
            }

            // Extract enhanced key usage
            var ekuExt = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
            if (ekuExt != null)
            {
                certInfo.EnhancedKeyUsage.AddRange(ekuExt.EnhancedKeyUsages.Cast<Oid>().Select(oid => oid.Value ?? string.Empty));
            }

            // Extract email addresses
            certInfo.EmailAddresses.AddRange(ExtractEmailAddresses(certificate));

            // Analyze algorithms
            await AnalyzeCertificateAlgorithmsAsync(certificate, certInfo);

            return certInfo;
        }

        private bool HasEmailInSan(X509Certificate2 certificate, string emailAddress)
        {
            var sanExtension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
            if (sanExtension == null) return false;

            try
            {
                // Parse SAN extension for email addresses
                var sanEmails = ExtractEmailAddresses(certificate);
                return sanEmails.Any(email => email.Equals(emailAddress, StringComparison.OrdinalIgnoreCase));
            }
            catch
            {
                return false;
            }
        }

        private List<string> ExtractEmailAddresses(X509Certificate2 certificate)
        {
            var emailAddresses = new List<string>();

            // Check subject for email
            var subjectParts = certificate.Subject.Split(',');
            foreach (var part in subjectParts)
            {
                var trimmedPart = part.Trim();
                if (trimmedPart.StartsWith("E=", StringComparison.OrdinalIgnoreCase) ||
                    trimmedPart.StartsWith("EMAILADDRESS=", StringComparison.OrdinalIgnoreCase))
                {
                    var email = trimmedPart.Split('=')[1].Trim();
                    if (!emailAddresses.Contains(email, StringComparer.OrdinalIgnoreCase))
                    {
                        emailAddresses.Add(email);
                    }
                }
            }

            // Check SAN extension
            var sanExtension = certificate.Extensions.OfType<X509SubjectAlternativeNameExtension>().FirstOrDefault();
            if (sanExtension != null)
            {
                // This is a simplified SAN parsing - in production, you might want more robust parsing
                var sanText = sanExtension.Format(false);
                var lines = sanText.Split('\n');
                foreach (var line in lines)
                {
                    if (line.Trim().StartsWith("RFC822 Name=", StringComparison.OrdinalIgnoreCase))
                    {
                        var email = line.Split('=')[1].Trim();
                        if (!emailAddresses.Contains(email, StringComparer.OrdinalIgnoreCase))
                        {
                            emailAddresses.Add(email);
                        }
                    }
                }
            }

            return emailAddresses;
        }

        private async Task AnalyzeCertificateAlgorithmsAsync(X509Certificate2 certificate, CertificateInfo certInfo)
        {
            // Check if this is a PQC certificate by examining the public key algorithm
            var publicKeyAlgorithm = certificate.GetKeyAlgorithm();
            
            // Common PQC algorithm OIDs (these would be standardized)
            var pqcAlgorithms = new Dictionary<string, string>
            {
                ["2.16.840.1.101.3.4.3.17"] = "ML-KEM-768", // Example OID
                ["2.16.840.1.101.3.4.3.44"] = "ML-DSA-65",  // Example OID
                // Add more PQC algorithm OIDs as they become standardized
            };

            if (pqcAlgorithms.ContainsKey(publicKeyAlgorithm))
            {
                certInfo.IsPqcCertificate = true;
                certInfo.PqcAlgorithm = new PqcAlgorithmInfo
                {
                    AlgorithmName = pqcAlgorithms[publicKeyAlgorithm],
                    ObjectIdentifier = publicKeyAlgorithm,
                    KeySize = certificate.GetPublicKey().Length * 8 // Convert to bits
                };
            }
            else
            {
                // Classical algorithm
                certInfo.ClassicalAlgorithm = new ClassicalAlgorithmInfo
                {
                    AlgorithmName = certificate.GetKeyAlgorithmParametersText(),
                    ObjectIdentifier = publicKeyAlgorithm,
                    KeySize = certificate.GetPublicKey().Length * 8
                };
            }

            // Check for hybrid certificates (would have custom extensions)
            var hybridExtension = certificate.Extensions.Cast<X509Extension>()
                .FirstOrDefault(ext => ext.Oid.Value == "1.2.3.4.5.6.7.8.9.10"); // Example hybrid extension OID

            if (hybridExtension != null)
            {
                certInfo.IsHybridCertificate = true;
                // Parse hybrid extension data here
            }
        }

        private async Task AnalyzePqcAlgorithmsAsync(X509Certificate2 certificate, CertificateValidationResult result)
        {
            // Add PQC-specific validation logic here
            // This could include checking algorithm parameters, key sizes, etc.
            
            var publicKeyAlgorithm = certificate.GetKeyAlgorithm();
            
            // Add metadata about the algorithms used
            result.Metadata["PublicKeyAlgorithm"] = publicKeyAlgorithm;
            result.Metadata["KeySize"] = certificate.GetPublicKey().Length * 8;
            
            // Add any PQC-specific validation warnings or information
            if (IsPqcAlgorithm(publicKeyAlgorithm))
            {
                result.Metadata["IsPqcCertificate"] = true;
                // Add PQC-specific validation logic
            }
        }

        private bool IsPqcAlgorithm(string algorithmOid)
        {
            // Check if the algorithm OID corresponds to a PQC algorithm
            var pqcAlgorithmOids = new[]
            {
                "2.16.840.1.101.3.4.3.17", // ML-KEM-768 (example)
                "2.16.840.1.101.3.4.3.44", // ML-DSA-65 (example)
                // Add more PQC algorithm OIDs
            };

            return pqcAlgorithmOids.Contains(algorithmOid);
        }

        private CertificateValidationStatus DetermineValidationStatus(X509ChainStatusFlags chainStatus, CertificateValidationStatus currentStatus)
        {
            // Determine the most severe validation status
            if (chainStatus.HasFlag(X509ChainStatusFlags.NotTimeValid))
            {
                return CertificateValidationStatus.Expired;
            }
            else if (chainStatus.HasFlag(X509ChainStatusFlags.NotTimeNested))
            {
                return CertificateValidationStatus.NotYetValid;
            }
            else if (chainStatus.HasFlag(X509ChainStatusFlags.Revoked))
            {
                return CertificateValidationStatus.Revoked;
            }
            else if (chainStatus.HasFlag(X509ChainStatusFlags.UntrustedRoot) ||
                    chainStatus.HasFlag(X509ChainStatusFlags.PartialChain))
            {
                return CertificateValidationStatus.Untrusted;
            }
            else if (chainStatus != X509ChainStatusFlags.NoError)
            {
                return CertificateValidationStatus.ChainValidationFailed;
            }

            return currentStatus;
        }

        private bool IsCertificateValid(X509Certificate2 certificate)
        {
            try
            {
                // Basic validity checks
                if (certificate == null) return false;
                if (DateTime.Now < certificate.NotBefore || DateTime.Now > certificate.NotAfter) return false;
                
                // Check if certificate has required extensions for email protection
                var ekuExt = certificate.Extensions.OfType<X509EnhancedKeyUsageExtension>().FirstOrDefault();
                if (ekuExt != null)
                {
                    var hasEmailProtection = ekuExt.EnhancedKeyUsages.Cast<Oid>()
                        .Any(oid => oid.Value == "1.3.6.1.5.5.7.3.4"); // Email protection OID
                    if (!hasEmailProtection) return false;
                }

                return true;
            }
            catch
            {
                return false;
            }
        }

        #endregion
    }
}