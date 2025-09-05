using System;
using System.Collections.Generic;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Represents the cryptographic capabilities of a recipient
    /// </summary>
    public class RecipientCapabilities
    {
        /// <summary>
        /// The email address of the recipient
        /// </summary>
        public string EmailAddress { get; set; } = string.Empty;

        /// <summary>
        /// Supported PQC KEM algorithms in order of preference
        /// </summary>
        public List<string> SupportedKemAlgorithms { get; set; } = new List<string>();

        /// <summary>
        /// Supported PQC signature algorithms in order of preference
        /// </summary>
        public List<string> SupportedSignatureAlgorithms { get; set; } = new List<string>();

        /// <summary>
        /// Supported classical algorithms for hybrid mode
        /// </summary>
        public List<string> SupportedClassicalAlgorithms { get; set; } = new List<string>();

        /// <summary>
        /// Supported cryptographic modes
        /// </summary>
        public List<CryptographicMode> SupportedModes { get; set; } = new List<CryptographicMode>();

        /// <summary>
        /// Whether the recipient supports hybrid encryption
        /// </summary>
        public bool SupportsHybrid => SupportedModes.Contains(CryptographicMode.Hybrid);

        /// <summary>
        /// Whether the recipient supports PQC-only encryption
        /// </summary>
        public bool SupportsPqcOnly => SupportedModes.Contains(CryptographicMode.PostQuantumOnly);

        /// <summary>
        /// Source of the capability information
        /// </summary>
        public CapabilitySource Source { get; set; }

        /// <summary>
        /// When the capabilities were discovered
        /// </summary>
        public DateTimeOffset DiscoveredAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// When the capabilities expire (for caching)
        /// </summary>
        public DateTimeOffset ExpiresAt { get; set; }

        /// <summary>
        /// Confidence level of the capability information (0.0 to 1.0)
        /// </summary>
        public double ConfidenceLevel { get; set; } = 1.0;

        /// <summary>
        /// Additional metadata about the capabilities
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();

        /// <summary>
        /// Whether the capabilities are still valid (not expired)
        /// </summary>
        public bool IsValid => DateTimeOffset.UtcNow < ExpiresAt;

        /// <summary>
        /// Gets the best supported KEM algorithm based on security preference
        /// </summary>
        /// <param name="preferredAlgorithms">Preferred algorithms in order</param>
        /// <returns>Best matching algorithm or null</returns>
        public string? GetBestKemAlgorithm(IEnumerable<string> preferredAlgorithms)
        {
            foreach (var preferred in preferredAlgorithms)
            {
                if (SupportedKemAlgorithms.Contains(preferred))
                    return preferred;
            }
            return SupportedKemAlgorithms.Count > 0 ? SupportedKemAlgorithms[0] : null;
        }

        /// <summary>
        /// Gets the best supported signature algorithm based on security preference
        /// </summary>
        /// <param name="preferredAlgorithms">Preferred algorithms in order</param>
        /// <returns>Best matching algorithm or null</returns>
        public string? GetBestSignatureAlgorithm(IEnumerable<string> preferredAlgorithms)
        {
            foreach (var preferred in preferredAlgorithms)
            {
                if (SupportedSignatureAlgorithms.Contains(preferred))
                    return preferred;
            }
            return SupportedSignatureAlgorithms.Count > 0 ? SupportedSignatureAlgorithms[0] : null;
        }
    }

    /// <summary>
    /// Source of capability discovery information
    /// </summary>
    public enum CapabilitySource
    {
        /// <summary>
        /// Discovered via DNS SMIMEA records
        /// </summary>
        SmimeaDns,

        /// <summary>
        /// Retrieved from Active Directory
        /// </summary>
        ActiveDirectory,

        /// <summary>
        /// Manually configured
        /// </summary>
        Manual,

        /// <summary>
        /// Cached from previous discovery
        /// </summary>
        Cache,

        /// <summary>
        /// Default fallback capabilities
        /// </summary>
        Fallback
    }

    /// <summary>
    /// Result of a capability discovery operation
    /// </summary>
    public class CapabilityDiscoveryResult
    {
        /// <summary>
        /// The discovered capabilities (null if not found)
        /// </summary>
        public RecipientCapabilities? Capabilities { get; set; }

        /// <summary>
        /// Whether the discovery was successful
        /// </summary>
        public bool IsSuccess => Capabilities != null && Error == null;

        /// <summary>
        /// Error information if discovery failed
        /// </summary>
        public CapabilityDiscoveryError? Error { get; set; }

        /// <summary>
        /// Time taken for the discovery operation
        /// </summary>
        public TimeSpan DiscoveryTime { get; set; }

        /// <summary>
        /// Whether the result came from cache
        /// </summary>
        public bool FromCache { get; set; }

        /// <summary>
        /// DNS query details if applicable
        /// </summary>
        public DnsQueryResult? DnsQuery { get; set; }

        /// <summary>
        /// Creates a successful discovery result
        /// </summary>
        /// <param name="capabilities">The discovered capabilities</param>
        /// <param name="discoveryTime">Time taken for discovery</param>
        /// <param name="fromCache">Whether result came from cache</param>
        /// <returns>Success result</returns>
        public static CapabilityDiscoveryResult Success(RecipientCapabilities capabilities, TimeSpan discoveryTime, bool fromCache = false)
        {
            return new CapabilityDiscoveryResult
            {
                Capabilities = capabilities,
                DiscoveryTime = discoveryTime,
                FromCache = fromCache
            };
        }

        /// <summary>
        /// Creates a failed discovery result
        /// </summary>
        /// <param name="error">The error that occurred</param>
        /// <param name="discoveryTime">Time taken for discovery</param>
        /// <returns>Failure result</returns>
        public static CapabilityDiscoveryResult Failure(CapabilityDiscoveryError error, TimeSpan discoveryTime)
        {
            return new CapabilityDiscoveryResult
            {
                Error = error,
                DiscoveryTime = discoveryTime
            };
        }
    }

    /// <summary>
    /// Error information for capability discovery failures
    /// </summary>
    public class CapabilityDiscoveryError
    {
        /// <summary>
        /// Type of error that occurred
        /// </summary>
        public CapabilityErrorType Type { get; set; }

        /// <summary>
        /// Human-readable error message
        /// </summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>
        /// Detailed error information
        /// </summary>
        public string? Details { get; set; }

        /// <summary>
        /// Inner exception if applicable
        /// </summary>
        public Exception? InnerException { get; set; }

        /// <summary>
        /// Whether this error should trigger a fallback attempt
        /// </summary>
        public bool ShouldFallback => Type == CapabilityErrorType.DnsTimeout ||
                                     Type == CapabilityErrorType.DnsServerError ||
                                     Type == CapabilityErrorType.ActiveDirectoryError;
    }

    /// <summary>
    /// Types of capability discovery errors
    /// </summary>
    public enum CapabilityErrorType
    {
        /// <summary>
        /// DNS query timed out
        /// </summary>
        DnsTimeout,

        /// <summary>
        /// DNS server returned an error
        /// </summary>
        DnsServerError,

        /// <summary>
        /// No SMIMEA record found
        /// </summary>
        NoSmimeaRecord,

        /// <summary>
        /// SMIMEA record format is invalid
        /// </summary>
        InvalidSmimeaRecord,

        /// <summary>
        /// Active Directory query failed
        /// </summary>
        ActiveDirectoryError,

        /// <summary>
        /// Certificate validation failed
        /// </summary>
        CertificateValidationError,

        /// <summary>
        /// Unknown or unexpected error
        /// </summary>
        Unknown
    }

    /// <summary>
    /// Result of a DNS query for SMIMEA records
    /// </summary>
    public class DnsQueryResult
    {
        /// <summary>
        /// The DNS query that was performed
        /// </summary>
        public string Query { get; set; } = string.Empty;

        /// <summary>
        /// DNS server that responded
        /// </summary>
        public string? DnsServer { get; set; }

        /// <summary>
        /// Response time for the DNS query
        /// </summary>
        public TimeSpan ResponseTime { get; set; }

        /// <summary>
        /// Whether DNSSEC validation was performed
        /// </summary>
        public bool DnssecValidated { get; set; }

        /// <summary>
        /// Raw DNS records returned
        /// </summary>
        public List<SmimeaRecord> SmimeaRecords { get; set; } = new List<SmimeaRecord>();

        /// <summary>
        /// Any errors encountered during DNS resolution
        /// </summary>
        public string? ErrorMessage { get; set; }
    }

    /// <summary>
    /// Represents a DNS SMIMEA record (RFC 8162)
    /// </summary>
    public class SmimeaRecord
    {
        /// <summary>
        /// Certificate usage field (0-3)
        /// </summary>
        public byte CertificateUsage { get; set; }

        /// <summary>
        /// Selector field (0-1)
        /// </summary>
        public byte Selector { get; set; }

        /// <summary>
        /// Matching type field (0-2)
        /// </summary>
        public byte MatchingType { get; set; }

        /// <summary>
        /// Certificate association data
        /// </summary>
        public byte[] CertificateAssociationData { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Raw SMIMEA record data
        /// </summary>
        public byte[] RawData { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Whether this record contains PQC algorithm information
        /// </summary>
        public bool IsPqcExtended { get; set; }

        /// <summary>
        /// PQC algorithm information if this is an extended record
        /// </summary>
        public List<string> PqcAlgorithms { get; set; } = new List<string>();
    }

    /// <summary>
    /// Configuration for capability discovery operations
    /// </summary>
    public class CapabilityDiscoveryConfiguration
    {
        /// <summary>
        /// Default cache TTL for discovered capabilities
        /// </summary>
        public TimeSpan DefaultCacheTtl { get; set; } = TimeSpan.FromHours(24);

        /// <summary>
        /// Timeout for DNS queries
        /// </summary>
        public TimeSpan DnsTimeout { get; set; } = TimeSpan.FromSeconds(5);

        /// <summary>
        /// Timeout for Active Directory queries
        /// </summary>
        public TimeSpan ActiveDirectoryTimeout { get; set; } = TimeSpan.FromSeconds(10);

        /// <summary>
        /// Maximum number of concurrent discovery operations
        /// </summary>
        public int MaxConcurrentDiscoveries { get; set; } = 10;

        /// <summary>
        /// Whether to enable DNSSEC validation
        /// </summary>
        public bool EnableDnssecValidation { get; set; } = true;

        /// <summary>
        /// Custom DNS servers to use (empty = use system default)
        /// </summary>
        public List<string> CustomDnsServers { get; set; } = new List<string>();

        /// <summary>
        /// Active Directory domain controller to query
        /// </summary>
        public string? ActiveDirectoryServer { get; set; }

        /// <summary>
        /// Whether to fall back to classical algorithms when PQC not available
        /// </summary>
        public bool EnableClassicalFallback { get; set; } = true;

        /// <summary>
        /// Default capabilities to assume when discovery fails
        /// </summary>
        public RecipientCapabilities? DefaultCapabilities { get; set; }

        /// <summary>
        /// Creates default configuration
        /// </summary>
        /// <returns>Default configuration</returns>
        public static CapabilityDiscoveryConfiguration CreateDefault()
        {
            return new CapabilityDiscoveryConfiguration
            {
                DefaultCapabilities = new RecipientCapabilities
                {
                    SupportedModes = new List<CryptographicMode> { CryptographicMode.Hybrid, CryptographicMode.ClassicalOnly },
                    SupportedKemAlgorithms = new List<string> { "ML-KEM-768", "RSA-OAEP-2048" },
                    SupportedSignatureAlgorithms = new List<string> { "ML-DSA-65", "RSA-PSS-2048" },
                    SupportedClassicalAlgorithms = new List<string> { "RSA-OAEP-2048", "RSA-PSS-2048" },
                    Source = CapabilitySource.Fallback,
                    ConfidenceLevel = 0.5
                }
            };
        }
    }
}