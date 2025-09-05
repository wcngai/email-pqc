using System;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Comprehensive information about a certificate including metadata and validation status
    /// </summary>
    public class CertificateInfo
    {
        /// <summary>
        /// The actual X.509 certificate
        /// </summary>
        public X509Certificate2 Certificate { get; set; } = null!;

        /// <summary>
        /// Certificate thumbprint (SHA-1 hash)
        /// </summary>
        public string Thumbprint => Certificate.Thumbprint;

        /// <summary>
        /// Certificate subject distinguished name
        /// </summary>
        public string Subject => Certificate.Subject;

        /// <summary>
        /// Certificate issuer distinguished name
        /// </summary>
        public string Issuer => Certificate.Issuer;

        /// <summary>
        /// Certificate validity start date
        /// </summary>
        public DateTime NotBefore => Certificate.NotBefore;

        /// <summary>
        /// Certificate validity end date
        /// </summary>
        public DateTime NotAfter => Certificate.NotAfter;

        /// <summary>
        /// Days until certificate expires
        /// </summary>
        public int DaysUntilExpiration => (int)(NotAfter - DateTime.Now).TotalDays;

        /// <summary>
        /// Whether certificate is currently valid (within date range)
        /// </summary>
        public bool IsCurrentlyValid => DateTime.Now >= NotBefore && DateTime.Now <= NotAfter;

        /// <summary>
        /// Certificate store location where found
        /// </summary>
        public StoreLocation StoreLocation { get; set; }

        /// <summary>
        /// Certificate store name where found
        /// </summary>
        public StoreName StoreName { get; set; }

        /// <summary>
        /// Whether certificate has a private key available
        /// </summary>
        public bool HasPrivateKey => Certificate.HasPrivateKey;

        /// <summary>
        /// Certificate key usage flags
        /// </summary>
        public X509KeyUsageFlags KeyUsage { get; set; }

        /// <summary>
        /// Enhanced key usage object identifiers
        /// </summary>
        public List<string> EnhancedKeyUsage { get; set; } = new List<string>();

        /// <summary>
        /// Email addresses associated with certificate (from SAN extension)
        /// </summary>
        public List<string> EmailAddresses { get; set; } = new List<string>();

        /// <summary>
        /// Whether this is a PQC (Post-Quantum Cryptography) certificate
        /// </summary>
        public bool IsPqcCertificate { get; set; }

        /// <summary>
        /// PQC algorithm information if applicable
        /// </summary>
        public PqcAlgorithmInfo? PqcAlgorithm { get; set; }

        /// <summary>
        /// Whether this is a hybrid certificate (PQC + classical)
        /// </summary>
        public bool IsHybridCertificate { get; set; }

        /// <summary>
        /// Classical algorithm information for hybrid certificates
        /// </summary>
        public ClassicalAlgorithmInfo? ClassicalAlgorithm { get; set; }

        /// <summary>
        /// Certificate chain validation status
        /// </summary>
        public CertificateValidationStatus ValidationStatus { get; set; }

        /// <summary>
        /// Certificate revocation status
        /// </summary>
        public RevocationStatus? RevocationStatus { get; set; }

        /// <summary>
        /// Additional certificate metadata
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();

        /// <summary>
        /// When this certificate information was last updated
        /// </summary>
        public DateTimeOffset LastUpdated { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// Gets the primary email address for this certificate
        /// </summary>
        public string? PrimaryEmailAddress => EmailAddresses.Count > 0 ? EmailAddresses[0] : null;

        /// <summary>
        /// Determines if certificate is suitable for specific usage
        /// </summary>
        /// <param name="usage">Intended certificate usage</param>
        /// <returns>True if certificate supports the usage</returns>
        public bool SupportsUsage(CertificateUsage usage)
        {
            return usage switch
            {
                CertificateUsage.DigitalSignature => KeyUsage.HasFlag(X509KeyUsageFlags.DigitalSignature) || 
                                                   EnhancedKeyUsage.Contains("1.3.6.1.5.5.7.3.4"), // Email protection
                CertificateUsage.DataEncryption => KeyUsage.HasFlag(X509KeyUsageFlags.DataEncipherment) || 
                                                  KeyUsage.HasFlag(X509KeyUsageFlags.KeyEncipherment) ||
                                                  EnhancedKeyUsage.Contains("1.3.6.1.5.5.7.3.4"), // Email protection
                CertificateUsage.KeyAgreement => KeyUsage.HasFlag(X509KeyUsageFlags.KeyAgreement),
                _ => false
            };
        }

        /// <summary>
        /// Creates a copy of this certificate info with updated validation status
        /// </summary>
        /// <param name="newStatus">New validation status</param>
        /// <returns>Updated certificate info copy</returns>
        public CertificateInfo WithValidationStatus(CertificateValidationStatus newStatus)
        {
            var copy = (CertificateInfo)MemberwiseClone();
            copy.ValidationStatus = newStatus;
            copy.LastUpdated = DateTimeOffset.UtcNow;
            return copy;
        }
    }

    /// <summary>
    /// PQC algorithm information
    /// </summary>
    public class PqcAlgorithmInfo
    {
        public string AlgorithmName { get; set; } = string.Empty;
        public string ObjectIdentifier { get; set; } = string.Empty;
        public int KeySize { get; set; }
        public int SecurityLevel { get; set; }
        public Dictionary<string, object> Parameters { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>
    /// Classical algorithm information for hybrid certificates
    /// </summary>
    public class ClassicalAlgorithmInfo
    {
        public string AlgorithmName { get; set; } = string.Empty;
        public string ObjectIdentifier { get; set; } = string.Empty;
        public int KeySize { get; set; }
        public Dictionary<string, object> Parameters { get; set; } = new Dictionary<string, object>();
    }
}