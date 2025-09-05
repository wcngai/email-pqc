using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Result of certificate validation operation
    /// </summary>
    public class CertificateValidationResult
    {
        /// <summary>
        /// Overall validation success status
        /// </summary>
        public bool IsValid { get; set; }

        /// <summary>
        /// Detailed validation status
        /// </summary>
        public CertificateValidationStatus Status { get; set; }

        /// <summary>
        /// Certificate chain status elements
        /// </summary>
        public List<X509ChainElement> ChainElements { get; set; } = new List<X509ChainElement>();

        /// <summary>
        /// Chain validation errors
        /// </summary>
        public List<X509ChainStatusFlags> ChainErrors { get; set; } = new List<X509ChainStatusFlags>();

        /// <summary>
        /// Detailed error messages
        /// </summary>
        public List<string> ErrorMessages { get; set; } = new List<string>();

        /// <summary>
        /// Warning messages (non-fatal issues)
        /// </summary>
        public List<string> WarningMessages { get; set; } = new List<string>();

        /// <summary>
        /// Validation timestamp
        /// </summary>
        public DateTimeOffset ValidationTime { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Trust root certificate
        /// </summary>
        public X509Certificate2? TrustRoot { get; set; }

        /// <summary>
        /// Whether revocation checking was performed
        /// </summary>
        public bool RevocationChecked { get; set; }

        /// <summary>
        /// Revocation check result
        /// </summary>
        public RevocationStatus? RevocationStatus { get; set; }

        /// <summary>
        /// Additional validation metadata
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();

        /// <summary>
        /// Creates a failed validation result with error message
        /// </summary>
        /// <param name="errorMessage">Error message</param>
        /// <param name="status">Validation status</param>
        /// <returns>Failed validation result</returns>
        public static CertificateValidationResult Failed(string errorMessage, CertificateValidationStatus status = CertificateValidationStatus.ValidationFailed)
        {
            return new CertificateValidationResult
            {
                IsValid = false,
                Status = status,
                ErrorMessages = { errorMessage }
            };
        }

        /// <summary>
        /// Creates a successful validation result
        /// </summary>
        /// <returns>Successful validation result</returns>
        public static CertificateValidationResult Success()
        {
            return new CertificateValidationResult
            {
                IsValid = true,
                Status = CertificateValidationStatus.Valid
            };
        }
    }

    /// <summary>
    /// Result of certificate installation operation
    /// </summary>
    public class CertificateInstallationResult
    {
        /// <summary>
        /// Installation success status
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Detailed installation status
        /// </summary>
        public InstallationStatus Status { get; set; }

        /// <summary>
        /// Installed certificate thumbprint
        /// </summary>
        public string? Thumbprint { get; set; }

        /// <summary>
        /// Target store location
        /// </summary>
        public StoreLocation StoreLocation { get; set; }

        /// <summary>
        /// Target store name
        /// </summary>
        public StoreName StoreName { get; set; }

        /// <summary>
        /// Error message if installation failed
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Exception details if applicable
        /// </summary>
        public Exception? Exception { get; set; }

        /// <summary>
        /// Installation timestamp
        /// </summary>
        public DateTimeOffset InstallationTime { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Creates a successful installation result
        /// </summary>
        /// <param name="thumbprint">Certificate thumbprint</param>
        /// <param name="storeLocation">Store location</param>
        /// <param name="storeName">Store name</param>
        /// <returns>Successful installation result</returns>
        public static CertificateInstallationResult Success(string thumbprint, StoreLocation storeLocation, StoreName storeName)
        {
            return new CertificateInstallationResult
            {
                Success = true,
                Status = InstallationStatus.Success,
                Thumbprint = thumbprint,
                StoreLocation = storeLocation,
                StoreName = storeName
            };
        }

        /// <summary>
        /// Creates a failed installation result
        /// </summary>
        /// <param name="status">Installation status</param>
        /// <param name="errorMessage">Error message</param>
        /// <param name="exception">Optional exception</param>
        /// <returns>Failed installation result</returns>
        public static CertificateInstallationResult Failed(InstallationStatus status, string errorMessage, Exception? exception = null)
        {
            return new CertificateInstallationResult
            {
                Success = false,
                Status = status,
                ErrorMessage = errorMessage,
                Exception = exception
            };
        }
    }

    /// <summary>
    /// Result of key storage operation
    /// </summary>
    public class KeyStorageResult
    {
        /// <summary>
        /// Storage operation success status
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Key container name where stored
        /// </summary>
        public string? ContainerName { get; set; }

        /// <summary>
        /// Storage type used
        /// </summary>
        public KeyStorageType StorageType { get; set; }

        /// <summary>
        /// Key fingerprint for verification
        /// </summary>
        public string? KeyFingerprint { get; set; }

        /// <summary>
        /// Error message if storage failed
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Exception details if applicable
        /// </summary>
        public Exception? Exception { get; set; }

        /// <summary>
        /// Storage timestamp
        /// </summary>
        public DateTimeOffset StorageTime { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// HSM information if stored in HSM
        /// </summary>
        public HsmInfo? HsmInfo { get; set; }

        /// <summary>
        /// Creates a successful storage result
        /// </summary>
        /// <param name="containerName">Container name</param>
        /// <param name="storageType">Storage type</param>
        /// <param name="keyFingerprint">Key fingerprint</param>
        /// <returns>Successful storage result</returns>
        public static KeyStorageResult Success(string containerName, KeyStorageType storageType, string keyFingerprint)
        {
            return new KeyStorageResult
            {
                Success = true,
                ContainerName = containerName,
                StorageType = storageType,
                KeyFingerprint = keyFingerprint
            };
        }

        /// <summary>
        /// Creates a failed storage result
        /// </summary>
        /// <param name="errorMessage">Error message</param>
        /// <param name="exception">Optional exception</param>
        /// <returns>Failed storage result</returns>
        public static KeyStorageResult Failed(string errorMessage, Exception? exception = null)
        {
            return new KeyStorageResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Exception = exception
            };
        }
    }

    /// <summary>
    /// Result of certificate enrollment operation
    /// </summary>
    public class EnrollmentResult
    {
        /// <summary>
        /// Enrollment success status
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Enrollment status
        /// </summary>
        public EnrollmentStatus Status { get; set; }

        /// <summary>
        /// Certificate request ID (if pending)
        /// </summary>
        public string? RequestId { get; set; }

        /// <summary>
        /// Issued certificate (if successful)
        /// </summary>
        public X509Certificate2? Certificate { get; set; }

        /// <summary>
        /// CA server that processed the request
        /// </summary>
        public string? CaServerName { get; set; }

        /// <summary>
        /// Certificate template used
        /// </summary>
        public string? TemplateName { get; set; }

        /// <summary>
        /// Error message if enrollment failed
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Exception details if applicable
        /// </summary>
        public Exception? Exception { get; set; }

        /// <summary>
        /// Enrollment timestamp
        /// </summary>
        public DateTimeOffset EnrollmentTime { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Expected certificate retrieval time (for pending requests)
        /// </summary>
        public DateTimeOffset? ExpectedRetrievalTime { get; set; }

        /// <summary>
        /// Creates a successful enrollment result
        /// </summary>
        /// <param name="certificate">Issued certificate</param>
        /// <param name="caServerName">CA server name</param>
        /// <returns>Successful enrollment result</returns>
        public static EnrollmentResult Success(X509Certificate2 certificate, string caServerName)
        {
            return new EnrollmentResult
            {
                Success = true,
                Status = EnrollmentStatus.Issued,
                Certificate = certificate,
                CaServerName = caServerName
            };
        }

        /// <summary>
        /// Creates a pending enrollment result
        /// </summary>
        /// <param name="requestId">Request ID</param>
        /// <param name="caServerName">CA server name</param>
        /// <param name="expectedRetrievalTime">Expected retrieval time</param>
        /// <returns>Pending enrollment result</returns>
        public static EnrollmentResult Pending(string requestId, string caServerName, DateTimeOffset? expectedRetrievalTime = null)
        {
            return new EnrollmentResult
            {
                Success = false,
                Status = EnrollmentStatus.Pending,
                RequestId = requestId,
                CaServerName = caServerName,
                ExpectedRetrievalTime = expectedRetrievalTime ?? DateTimeOffset.UtcNow.AddMinutes(15)
            };
        }

        /// <summary>
        /// Creates a failed enrollment result
        /// </summary>
        /// <param name="status">Enrollment status</param>
        /// <param name="errorMessage">Error message</param>
        /// <param name="exception">Optional exception</param>
        /// <returns>Failed enrollment result</returns>
        public static EnrollmentResult Failed(EnrollmentStatus status, string errorMessage, Exception? exception = null)
        {
            return new EnrollmentResult
            {
                Success = false,
                Status = status,
                ErrorMessage = errorMessage,
                Exception = exception
            };
        }
    }

    /// <summary>
    /// Result of certificate backup operation
    /// </summary>
    public class CertificateBackupResult
    {
        /// <summary>
        /// Backup operation success status
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Backup file path
        /// </summary>
        public string? BackupFilePath { get; set; }

        /// <summary>
        /// Backup format used
        /// </summary>
        public BackupFormat Format { get; set; }

        /// <summary>
        /// Number of certificates backed up
        /// </summary>
        public int CertificateCount { get; set; }

        /// <summary>
        /// Backup file size in bytes
        /// </summary>
        public long BackupFileSize { get; set; }

        /// <summary>
        /// Backup timestamp
        /// </summary>
        public DateTimeOffset BackupTime { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Error message if backup failed
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Exception details if applicable
        /// </summary>
        public Exception? Exception { get; set; }

        /// <summary>
        /// SHA-256 hash of backup file for integrity verification
        /// </summary>
        public string? BackupFileHash { get; set; }

        /// <summary>
        /// Creates a successful backup result
        /// </summary>
        /// <param name="backupFilePath">Backup file path</param>
        /// <param name="format">Backup format</param>
        /// <param name="certificateCount">Number of certificates</param>
        /// <param name="fileSize">File size</param>
        /// <param name="fileHash">File hash</param>
        /// <returns>Successful backup result</returns>
        public static CertificateBackupResult Success(string backupFilePath, BackupFormat format, int certificateCount, long fileSize, string fileHash)
        {
            return new CertificateBackupResult
            {
                Success = true,
                BackupFilePath = backupFilePath,
                Format = format,
                CertificateCount = certificateCount,
                BackupFileSize = fileSize,
                BackupFileHash = fileHash
            };
        }

        /// <summary>
        /// Creates a failed backup result
        /// </summary>
        /// <param name="errorMessage">Error message</param>
        /// <param name="exception">Optional exception</param>
        /// <returns>Failed backup result</returns>
        public static CertificateBackupResult Failed(string errorMessage, Exception? exception = null)
        {
            return new CertificateBackupResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Exception = exception
            };
        }
    }

    /// <summary>
    /// Result of certificate restore operation
    /// </summary>
    public class CertificateRestoreResult
    {
        /// <summary>
        /// Restore operation success status
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Number of certificates restored
        /// </summary>
        public int RestoredCertificateCount { get; set; }

        /// <summary>
        /// Number of certificates that failed to restore
        /// </summary>
        public int FailedCertificateCount { get; set; }

        /// <summary>
        /// List of restored certificate thumbprints
        /// </summary>
        public List<string> RestoredCertificates { get; set; } = new List<string>();

        /// <summary>
        /// List of failed certificate details
        /// </summary>
        public List<string> FailedCertificates { get; set; } = new List<string>();

        /// <summary>
        /// Restore timestamp
        /// </summary>
        public DateTimeOffset RestoreTime { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Error message if restore failed completely
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Exception details if applicable
        /// </summary>
        public Exception? Exception { get; set; }

        /// <summary>
        /// Creates a successful restore result
        /// </summary>
        /// <param name="restoredCertificates">List of restored certificate thumbprints</param>
        /// <returns>Successful restore result</returns>
        public static CertificateRestoreResult Success(List<string> restoredCertificates)
        {
            return new CertificateRestoreResult
            {
                Success = true,
                RestoredCertificateCount = restoredCertificates.Count,
                RestoredCertificates = restoredCertificates
            };
        }

        /// <summary>
        /// Creates a partially successful restore result
        /// </summary>
        /// <param name="restoredCertificates">Successfully restored certificates</param>
        /// <param name="failedCertificates">Failed certificate details</param>
        /// <returns>Partial restore result</returns>
        public static CertificateRestoreResult Partial(List<string> restoredCertificates, List<string> failedCertificates)
        {
            return new CertificateRestoreResult
            {
                Success = restoredCertificates.Count > 0,
                RestoredCertificateCount = restoredCertificates.Count,
                FailedCertificateCount = failedCertificates.Count,
                RestoredCertificates = restoredCertificates,
                FailedCertificates = failedCertificates
            };
        }

        /// <summary>
        /// Creates a failed restore result
        /// </summary>
        /// <param name="errorMessage">Error message</param>
        /// <param name="exception">Optional exception</param>
        /// <returns>Failed restore result</returns>
        public static CertificateRestoreResult Failed(string errorMessage, Exception? exception = null)
        {
            return new CertificateRestoreResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Exception = exception
            };
        }
    }

    /// <summary>
    /// Result of key archival operation
    /// </summary>
    public class KeyArchivalResult
    {
        /// <summary>
        /// Archival operation success status
        /// </summary>
        public bool Success { get; set; }

        /// <summary>
        /// Archived key information
        /// </summary>
        public KeyPairInfo? ArchivedKeyInfo { get; set; }

        /// <summary>
        /// Original key ID that was archived
        /// </summary>
        public string? OriginalKeyId { get; set; }

        /// <summary>
        /// Archival reason
        /// </summary>
        public string? ArchivalReason { get; set; }

        /// <summary>
        /// Archival timestamp
        /// </summary>
        public DateTimeOffset ArchivalTime { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Error message if archival failed
        /// </summary>
        public string? ErrorMessage { get; set; }

        /// <summary>
        /// Exception details if applicable
        /// </summary>
        public Exception? Exception { get; set; }

        /// <summary>
        /// Creates a successful archival result
        /// </summary>
        /// <param name="archivedKeyInfo">Archived key information</param>
        /// <param name="originalKeyId">Original key ID</param>
        /// <param name="reason">Archival reason</param>
        /// <returns>Successful archival result</returns>
        public static KeyArchivalResult Success(KeyPairInfo archivedKeyInfo, string originalKeyId, string reason)
        {
            return new KeyArchivalResult
            {
                Success = true,
                ArchivedKeyInfo = archivedKeyInfo,
                OriginalKeyId = originalKeyId,
                ArchivalReason = reason
            };
        }

        /// <summary>
        /// Creates a failed archival result
        /// </summary>
        /// <param name="errorMessage">Error message</param>
        /// <param name="exception">Optional exception</param>
        /// <returns>Failed archival result</returns>
        public static KeyArchivalResult Failed(string errorMessage, Exception? exception = null)
        {
            return new KeyArchivalResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Exception = exception
            };
        }
    }

    /// <summary>
    /// Additional models for enrollment and validation
    /// </summary>
    public class CaCredentials
    {
        public string Username { get; set; } = string.Empty;
        public string Password { get; set; } = string.Empty;
        public string? ApiKey { get; set; }
        public string? ClientCertificateThumbprint { get; set; }
        public Dictionary<string, string> AdditionalHeaders { get; set; } = new Dictionary<string, string>();
    }

    /// <summary>
    /// Certificate revocation result
    /// </summary>
    public class RevocationResult
    {
        public bool Success { get; set; }
        public string? RevocationId { get; set; }
        public CrlReason Reason { get; set; }
        public DateTimeOffset RevocationTime { get; set; } = DateTimeOffset.UtcNow;
        public string? ErrorMessage { get; set; }
        public Exception? Exception { get; set; }

        public static RevocationResult Success(string revocationId, CrlReason reason)
        {
            return new RevocationResult
            {
                Success = true,
                RevocationId = revocationId,
                Reason = reason
            };
        }

        public static RevocationResult Failed(string errorMessage, Exception? exception = null)
        {
            return new RevocationResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Exception = exception
            };
        }
    }

    /// <summary>
    /// Enrollment configuration validation result
    /// </summary>
    public class EnrollmentConfigurationValidationResult
    {
        public bool IsValid { get; set; }
        public string? CaServerName { get; set; }
        public string? TemplateName { get; set; }
        public List<string> SupportedAlgorithms { get; set; } = new List<string>();
        public List<string> ValidationErrors { get; set; } = new List<string>();
        public List<string> ValidationWarnings { get; set; } = new List<string>();
        public DateTimeOffset ValidationTime { get; set; } = DateTimeOffset.UtcNow;

        public static EnrollmentConfigurationValidationResult Valid(string caServerName, string templateName, List<string> supportedAlgorithms)
        {
            return new EnrollmentConfigurationValidationResult
            {
                IsValid = true,
                CaServerName = caServerName,
                TemplateName = templateName,
                SupportedAlgorithms = supportedAlgorithms
            };
        }

        public static EnrollmentConfigurationValidationResult Invalid(List<string> errors)
        {
            return new EnrollmentConfigurationValidationResult
            {
                IsValid = false,
                ValidationErrors = errors
            };
        }
    }
}