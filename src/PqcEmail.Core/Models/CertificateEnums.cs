using System;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Certificate usage types for dual keypair architecture
    /// </summary>
    public enum CertificateUsage
    {
        /// <summary>
        /// Certificate used for digital signatures
        /// </summary>
        DigitalSignature,

        /// <summary>
        /// Certificate used for data encryption
        /// </summary>
        DataEncryption,

        /// <summary>
        /// Certificate used for key agreement (ECDH, etc.)
        /// </summary>
        KeyAgreement
    }

    /// <summary>
    /// Key usage types for keypair management
    /// </summary>
    public enum KeyUsage
    {
        /// <summary>
        /// Key used for signing operations
        /// </summary>
        Signing,

        /// <summary>
        /// Key used for encryption operations
        /// </summary>
        Encryption,

        /// <summary>
        /// Key used for key agreement/exchange
        /// </summary>
        KeyAgreement
    }

    /// <summary>
    /// Certificate validation status
    /// </summary>
    public enum CertificateValidationStatus
    {
        /// <summary>
        /// Certificate validation not yet performed
        /// </summary>
        NotValidated,

        /// <summary>
        /// Certificate is valid and trusted
        /// </summary>
        Valid,

        /// <summary>
        /// Certificate is expired
        /// </summary>
        Expired,

        /// <summary>
        /// Certificate is revoked
        /// </summary>
        Revoked,

        /// <summary>
        /// Certificate chain validation failed
        /// </summary>
        ChainValidationFailed,

        /// <summary>
        /// Certificate is not yet valid
        /// </summary>
        NotYetValid,

        /// <summary>
        /// Certificate is untrusted
        /// </summary>
        Untrusted,

        /// <summary>
        /// Certificate validation failed for unknown reason
        /// </summary>
        ValidationFailed
    }

    /// <summary>
    /// Certificate revocation status
    /// </summary>
    public enum RevocationStatus
    {
        /// <summary>
        /// Revocation status not checked
        /// </summary>
        NotChecked,

        /// <summary>
        /// Certificate is not revoked
        /// </summary>
        NotRevoked,

        /// <summary>
        /// Certificate is revoked
        /// </summary>
        Revoked,

        /// <summary>
        /// Revocation status unknown (OCSP/CRL unavailable)
        /// </summary>
        Unknown,

        /// <summary>
        /// Error occurred while checking revocation status
        /// </summary>
        Error
    }

    /// <summary>
    /// Certificate revocation reasons (RFC 5280)
    /// </summary>
    public enum CrlReason
    {
        /// <summary>
        /// Unspecified reason
        /// </summary>
        Unspecified = 0,

        /// <summary>
        /// Key compromise
        /// </summary>
        KeyCompromise = 1,

        /// <summary>
        /// Certificate Authority compromise
        /// </summary>
        CaCompromise = 2,

        /// <summary>
        /// Affiliation changed
        /// </summary>
        AffiliationChanged = 3,

        /// <summary>
        /// Certificate superseded
        /// </summary>
        Superseded = 4,

        /// <summary>
        /// Cessation of operation
        /// </summary>
        CessationOfOperation = 5,

        /// <summary>
        /// Certificate hold (temporary)
        /// </summary>
        CertificateHold = 6,

        /// <summary>
        /// Privilege withdrawn
        /// </summary>
        PrivilegeWithdrawn = 9,

        /// <summary>
        /// AA compromise
        /// </summary>
        AaCompromise = 10
    }

    /// <summary>
    /// Certificate installation result status
    /// </summary>
    public enum InstallationStatus
    {
        /// <summary>
        /// Certificate installed successfully
        /// </summary>
        Success,

        /// <summary>
        /// Certificate already exists in store
        /// </summary>
        AlreadyExists,

        /// <summary>
        /// Access denied to certificate store
        /// </summary>
        AccessDenied,

        /// <summary>
        /// Invalid certificate format
        /// </summary>
        InvalidCertificate,

        /// <summary>
        /// Store not found or inaccessible
        /// </summary>
        StoreNotFound,

        /// <summary>
        /// Installation failed for unknown reason
        /// </summary>
        Failed
    }

    /// <summary>
    /// Certificate enrollment status
    /// </summary>
    public enum EnrollmentStatus
    {
        /// <summary>
        /// Enrollment request created
        /// </summary>
        RequestCreated,

        /// <summary>
        /// Enrollment request submitted
        /// </summary>
        RequestSubmitted,

        /// <summary>
        /// Enrollment request pending CA approval
        /// </summary>
        Pending,

        /// <summary>
        /// Certificate issued successfully
        /// </summary>
        Issued,

        /// <summary>
        /// Enrollment request denied
        /// </summary>
        Denied,

        /// <summary>
        /// Enrollment request failed
        /// </summary>
        Failed,

        /// <summary>
        /// Enrollment request expired
        /// </summary>
        Expired
    }

    /// <summary>
    /// Key storage location types
    /// </summary>
    public enum KeyStorageType
    {
        /// <summary>
        /// Windows CNG key storage
        /// </summary>
        WindowsCng,

        /// <summary>
        /// Hardware Security Module
        /// </summary>
        HardwareSecurityModule,

        /// <summary>
        /// PKCS#11 token
        /// </summary>
        Pkcs11Token,

        /// <summary>
        /// Software key container
        /// </summary>
        SoftwareContainer
    }

    /// <summary>
    /// Certificate backup format types
    /// </summary>
    public enum BackupFormat
    {
        /// <summary>
        /// PKCS#12 format (.pfx/.p12)
        /// </summary>
        Pkcs12,

        /// <summary>
        /// Custom encrypted format
        /// </summary>
        EncryptedCustom,

        /// <summary>
        /// PEM format with encrypted private keys
        /// </summary>
        EncryptedPem
    }

    /// <summary>
    /// HSM authentication methods
    /// </summary>
    public enum HsmAuthMethod
    {
        /// <summary>
        /// PIN-based authentication
        /// </summary>
        Pin,

        /// <summary>
        /// Password-based authentication
        /// </summary>
        Password,

        /// <summary>
        /// Certificate-based authentication
        /// </summary>
        Certificate,

        /// <summary>
        /// Biometric authentication
        /// </summary>
        Biometric,

        /// <summary>
        /// Multi-factor authentication
        /// </summary>
        MultiFactor
    }
}