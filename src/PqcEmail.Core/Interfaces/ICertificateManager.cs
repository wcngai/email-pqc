using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Interfaces
{
    /// <summary>
    /// Core interface for certificate management operations including discovery, validation, and lifecycle management
    /// </summary>
    public interface ICertificateManager
    {
        /// <summary>
        /// Discovers certificates for a specific email address across all accessible stores
        /// </summary>
        /// <param name="emailAddress">Target email address</param>
        /// <param name="storeName">Optional store name filter</param>
        /// <returns>Collection of discovered certificates with metadata</returns>
        Task<IEnumerable<CertificateInfo>> DiscoverCertificatesAsync(string emailAddress, StoreName? storeName = null);

        /// <summary>
        /// Validates a certificate chain including PQC and classical certificates
        /// </summary>
        /// <param name="certificate">Certificate to validate</param>
        /// <param name="chainPolicy">Optional custom chain policy</param>
        /// <returns>Validation result with detailed status</returns>
        Task<CertificateValidationResult> ValidateCertificateChainAsync(X509Certificate2 certificate, X509ChainPolicy? chainPolicy = null);

        /// <summary>
        /// Installs a certificate to the appropriate Windows Certificate Store
        /// </summary>
        /// <param name="certificate">Certificate to install</param>
        /// <param name="storeName">Target store name</param>
        /// <param name="storeLocation">Target store location</param>
        /// <returns>Installation result</returns>
        Task<CertificateInstallationResult> InstallCertificateAsync(X509Certificate2 certificate, StoreName storeName, StoreLocation storeLocation);

        /// <summary>
        /// Removes a certificate from Windows Certificate Store
        /// </summary>
        /// <param name="thumbprint">Certificate thumbprint</param>
        /// <param name="storeName">Store name</param>
        /// <param name="storeLocation">Store location</param>
        /// <returns>Removal result</returns>
        Task<bool> RemoveCertificateAsync(string thumbprint, StoreName storeName, StoreLocation storeLocation);

        /// <summary>
        /// Gets all certificates nearing expiration
        /// </summary>
        /// <param name="warningDays">Days before expiration to warn</param>
        /// <returns>Collection of expiring certificates</returns>
        Task<IEnumerable<CertificateInfo>> GetExpiringCertificatesAsync(int warningDays = 30);

        /// <summary>
        /// Checks certificate revocation status using OCSP and CRL
        /// </summary>
        /// <param name="certificate">Certificate to check</param>
        /// <returns>Revocation status result</returns>
        Task<RevocationStatus> CheckRevocationStatusAsync(X509Certificate2 certificate);

        /// <summary>
        /// Finds the best certificate for a given email address and operation type
        /// </summary>
        /// <param name="emailAddress">Target email address</param>
        /// <param name="operationType">Type of cryptographic operation</param>
        /// <returns>Best matching certificate or null</returns>
        Task<X509Certificate2?> FindBestCertificateAsync(string emailAddress, CertificateUsage operationType);

        /// <summary>
        /// Backs up certificates and private keys to encrypted storage
        /// </summary>
        /// <param name="certificates">Certificates to backup</param>
        /// <param name="backupPath">Path to backup location</param>
        /// <param name="password">Encryption password</param>
        /// <returns>Backup operation result</returns>
        Task<CertificateBackupResult> BackupCertificatesAsync(IEnumerable<X509Certificate2> certificates, string backupPath, string password);

        /// <summary>
        /// Restores certificates from encrypted backup
        /// </summary>
        /// <param name="backupPath">Path to backup file</param>
        /// <param name="password">Decryption password</param>
        /// <returns>Restore operation result</returns>
        Task<CertificateRestoreResult> RestoreCertificatesAsync(string backupPath, string password);
    }
}