using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Represents the complete policy configuration for PQC email encryption.
    /// </summary>
    public class PqcEmailPolicy
    {
        /// <summary>
        /// Gets or sets the global cryptographic configuration.
        /// </summary>
        public GlobalCryptographicPolicy GlobalCryptographic { get; set; } = new();

        /// <summary>
        /// Gets or sets the security enforcement policies.
        /// </summary>
        public SecurityPolicy Security { get; set; } = new();

        /// <summary>
        /// Gets or sets the domain-based encryption rules.
        /// </summary>
        public DomainPolicy Domain { get; set; } = new();

        /// <summary>
        /// Gets or sets the policy inheritance and override settings.
        /// </summary>
        public InheritancePolicy Inheritance { get; set; } = new();

        /// <summary>
        /// Gets or sets the fallback and degradation policies.
        /// </summary>
        public FallbackPolicy Fallback { get; set; } = new();

        /// <summary>
        /// Gets or sets the audit and logging policies.
        /// </summary>
        public AuditPolicy Audit { get; set; } = new();

        /// <summary>
        /// Gets or sets the performance and resource limit policies.
        /// </summary>
        public PerformancePolicy Performance { get; set; } = new();

        /// <summary>
        /// Gets or sets the certificate and key management policies.
        /// </summary>
        public CertificatePolicy Certificate { get; set; } = new();

        /// <summary>
        /// Gets or sets the timestamp when this policy was last updated.
        /// </summary>
        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Gets or sets the version of this policy configuration.
        /// </summary>
        public string Version { get; set; } = "1.0";

        /// <summary>
        /// Gets or sets the source of this policy (GroupPolicy, Registry, Configuration, etc.).
        /// </summary>
        public PolicySource Source { get; set; } = PolicySource.Default;
    }

    /// <summary>
    /// Represents global cryptographic policy settings.
    /// </summary>
    public class GlobalCryptographicPolicy
    {
        /// <summary>
        /// Gets or sets the global cryptographic mode.
        /// </summary>
        public CryptographicMode Mode { get; set; } = CryptographicMode.Hybrid;

        /// <summary>
        /// Gets or sets the preferred post-quantum KEM algorithm.
        /// </summary>
        public string PreferredKemAlgorithm { get; set; } = "ML-KEM-768";

        /// <summary>
        /// Gets or sets the preferred post-quantum signature algorithm.
        /// </summary>
        public string PreferredSignatureAlgorithm { get; set; } = "ML-DSA-65";

        /// <summary>
        /// Gets or sets the fallback classical KEM algorithm.
        /// </summary>
        public string FallbackKemAlgorithm { get; set; } = "RSA-OAEP-2048";

        /// <summary>
        /// Gets or sets the fallback classical signature algorithm.
        /// </summary>
        public string FallbackSignatureAlgorithm { get; set; } = "RSA-PSS-2048";

        /// <summary>
        /// Gets or sets whether dual signatures are always created in hybrid mode.
        /// </summary>
        public bool AlwaysCreateDualSignatures { get; set; } = true;
    }

    /// <summary>
    /// Represents security enforcement policies.
    /// </summary>
    public class SecurityPolicy
    {
        /// <summary>
        /// Gets or sets the minimum acceptable RSA key size in bits.
        /// </summary>
        public int MinimumRsaKeySize { get; set; } = 2048;

        /// <summary>
        /// Gets or sets whether weak algorithms are prohibited.
        /// </summary>
        public bool ProhibitWeakAlgorithms { get; set; } = true;

        /// <summary>
        /// Gets or sets whether hardware protection (HSM) is required.
        /// </summary>
        public bool RequireHardwareProtection { get; set; } = false;

        /// <summary>
        /// Gets or sets the list of explicitly prohibited algorithms.
        /// </summary>
        public List<string> ProhibitedAlgorithms { get; set; } = new()
        {
            "MD5", "SHA1", "RSA-1024", "DES", "3DES"
        };

        /// <summary>
        /// Gets or sets the minimum security level required for operations.
        /// </summary>
        public SecurityLevel MinimumSecurityLevel { get; set; } = SecurityLevel.Standard;
    }

    /// <summary>
    /// Represents domain-based encryption policies.
    /// </summary>
    public class DomainPolicy
    {
        /// <summary>
        /// Gets or sets domains that must use post-quantum cryptography.
        /// </summary>
        public List<DomainRule> ForcePqcDomains { get; set; } = new();

        /// <summary>
        /// Gets or sets domains that prohibit unencrypted email.
        /// </summary>
        public List<DomainRule> ProhibitUnencryptedDomains { get; set; } = new();

        /// <summary>
        /// Gets or sets domains that allow classical-only encryption.
        /// </summary>
        public List<DomainRule> AllowClassicalOnlyDomains { get; set; } = new();

        /// <summary>
        /// Gets or sets per-domain specific encryption overrides.
        /// </summary>
        public Dictionary<string, DomainSpecificPolicy> DomainOverrides { get; set; } = new();

        /// <summary>
        /// Gets or sets per-recipient specific encryption overrides.
        /// </summary>
        public Dictionary<string, RecipientSpecificPolicy> RecipientOverrides { get; set; } = new();
    }

    /// <summary>
    /// Represents a domain rule with pattern matching.
    /// </summary>
    public class DomainRule
    {
        /// <summary>
        /// Gets or sets the domain pattern (supports wildcards).
        /// </summary>
        public string Pattern { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets whether this rule is enabled.
        /// </summary>
        public bool Enabled { get; set; } = true;

        /// <summary>
        /// Gets or sets an optional description for this rule.
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// Gets or sets the priority of this rule (higher number = higher priority).
        /// </summary>
        public int Priority { get; set; } = 100;

        /// <summary>
        /// Checks if the given domain matches this rule's pattern.
        /// </summary>
        /// <param name="domain">The domain to check</param>
        /// <returns>True if the domain matches the pattern</returns>
        public bool Matches(string domain)
        {
            if (string.IsNullOrEmpty(Pattern) || string.IsNullOrEmpty(domain))
                return false;

            // Convert wildcard pattern to regex
            var regexPattern = "^" + Regex.Escape(Pattern)
                .Replace(@"\*", ".*")
                .Replace(@"\?", ".") + "$";

            return Regex.IsMatch(domain, regexPattern, RegexOptions.IgnoreCase);
        }
    }

    /// <summary>
    /// Represents domain-specific policy overrides.
    /// </summary>
    public class DomainSpecificPolicy
    {
        /// <summary>
        /// Gets or sets the cryptographic mode override for this domain.
        /// </summary>
        public CryptographicMode? ModeOverride { get; set; }

        /// <summary>
        /// Gets or sets the preferred algorithm overrides for this domain.
        /// </summary>
        public AlgorithmOverrides? AlgorithmOverrides { get; set; }

        /// <summary>
        /// Gets or sets the security level override for this domain.
        /// </summary>
        public SecurityLevel? SecurityLevelOverride { get; set; }

        /// <summary>
        /// Gets or sets whether encryption is mandatory for this domain.
        /// </summary>
        public bool? RequireEncryption { get; set; }
    }

    /// <summary>
    /// Represents recipient-specific policy overrides.
    /// </summary>
    public class RecipientSpecificPolicy
    {
        /// <summary>
        /// Gets or sets the cryptographic mode override for this recipient.
        /// </summary>
        public CryptographicMode? ModeOverride { get; set; }

        /// <summary>
        /// Gets or sets the preferred algorithm overrides for this recipient.
        /// </summary>
        public AlgorithmOverrides? AlgorithmOverrides { get; set; }

        /// <summary>
        /// Gets or sets whether this recipient can be contacted without encryption.
        /// </summary>
        public bool? AllowUnencrypted { get; set; }

        /// <summary>
        /// Gets or sets the expiration time for this override.
        /// </summary>
        public DateTime? ExpiresAt { get; set; }
    }

    /// <summary>
    /// Represents algorithm-specific overrides.
    /// </summary>
    public class AlgorithmOverrides
    {
        /// <summary>
        /// Gets or sets the preferred KEM algorithm override.
        /// </summary>
        public string? PreferredKemAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the preferred signature algorithm override.
        /// </summary>
        public string? PreferredSignatureAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the fallback KEM algorithm override.
        /// </summary>
        public string? FallbackKemAlgorithm { get; set; }

        /// <summary>
        /// Gets or sets the fallback signature algorithm override.
        /// </summary>
        public string? FallbackSignatureAlgorithm { get; set; }
    }

    /// <summary>
    /// Represents policy inheritance and override settings.
    /// </summary>
    public class InheritancePolicy
    {
        /// <summary>
        /// Gets or sets whether users can override organizational policies.
        /// </summary>
        public bool AllowUserOverrides { get; set; } = false;

        /// <summary>
        /// Gets or sets whether domain-specific policies can override global settings.
        /// </summary>
        public bool AllowDomainOverrides { get; set; } = true;

        /// <summary>
        /// Gets or sets the policy override mode.
        /// </summary>
        public OverrideMode OverrideMode { get; set; } = OverrideMode.Balanced;

        /// <summary>
        /// Gets or sets the list of settings that cannot be overridden.
        /// </summary>
        public List<string> ProtectedSettings { get; set; } = new()
        {
            "MinimumRsaKeySize",
            "ProhibitWeakAlgorithms",
            "ProhibitedAlgorithms"
        };
    }

    /// <summary>
    /// Represents fallback and degradation policies.
    /// </summary>
    public class FallbackPolicy
    {
        /// <summary>
        /// Gets or sets whether unencrypted fallback is allowed.
        /// </summary>
        public bool AllowUnencryptedFallback { get; set; } = false;

        /// <summary>
        /// Gets or sets the maximum number of fallback attempts.
        /// </summary>
        public int MaxFallbackAttempts { get; set; } = 3;

        /// <summary>
        /// Gets or sets the timeout for each fallback attempt in seconds.
        /// </summary>
        public int FallbackTimeoutSeconds { get; set; } = 30;

        /// <summary>
        /// Gets or sets the custom fallback algorithm sequence.
        /// </summary>
        public List<FallbackStep> CustomFallbackSequence { get; set; } = new();
    }

    /// <summary>
    /// Represents a step in the fallback sequence.
    /// </summary>
    public class FallbackStep
    {
        /// <summary>
        /// Gets or sets the KEM algorithm for this fallback step.
        /// </summary>
        public string KemAlgorithm { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the signature algorithm for this fallback step.
        /// </summary>
        public string SignatureAlgorithm { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the timeout for this step in seconds.
        /// </summary>
        public int TimeoutSeconds { get; set; } = 30;

        /// <summary>
        /// Gets or sets the description of this fallback step.
        /// </summary>
        public string? Description { get; set; }
    }

    /// <summary>
    /// Represents audit and logging policies.
    /// </summary>
    public class AuditPolicy
    {
        /// <summary>
        /// Gets or sets whether detailed logging is enabled.
        /// </summary>
        public bool EnableDetailedLogging { get; set; } = true;

        /// <summary>
        /// Gets or sets whether policy decisions are logged.
        /// </summary>
        public bool LogPolicyDecisions { get; set; } = true;

        /// <summary>
        /// Gets or sets whether fallback events are logged.
        /// </summary>
        public bool LogFallbackEvents { get; set; } = true;

        /// <summary>
        /// Gets or sets whether security violations are logged.
        /// </summary>
        public bool LogSecurityViolations { get; set; } = true;

        /// <summary>
        /// Gets or sets the custom log file path.
        /// </summary>
        public string? CustomLogPath { get; set; }

        /// <summary>
        /// Gets or sets the minimum log level.
        /// </summary>
        public LogLevel LogLevel { get; set; } = LogLevel.Information;

        /// <summary>
        /// Gets or sets whether to log sensitive data (for debugging only).
        /// </summary>
        public bool LogSensitiveData { get; set; } = false;
    }

    /// <summary>
    /// Represents performance and resource policies.
    /// </summary>
    public class PerformancePolicy
    {
        /// <summary>
        /// Gets or sets the maximum operation time in milliseconds.
        /// </summary>
        public int MaxOperationTimeMs { get; set; } = 2000;

        /// <summary>
        /// Gets or sets the maximum memory usage in megabytes.
        /// </summary>
        public int MaxMemoryUsageMB { get; set; } = 100;

        /// <summary>
        /// Gets or sets the cache expiry time in minutes.
        /// </summary>
        public int CacheExpiryMinutes { get; set; } = 60;

        /// <summary>
        /// Gets or sets whether performance monitoring is enabled.
        /// </summary>
        public bool EnablePerformanceMonitoring { get; set; } = true;

        /// <summary>
        /// Gets or sets the maximum number of concurrent operations.
        /// </summary>
        public int MaxConcurrentOperations { get; set; } = 10;
    }

    /// <summary>
    /// Represents certificate and key management policies.
    /// </summary>
    public class CertificatePolicy
    {
        /// <summary>
        /// Gets or sets whether valid certificate chains are required.
        /// </summary>
        public bool RequireValidCertChain { get; set; } = true;

        /// <summary>
        /// Gets or sets whether self-signed certificates are allowed.
        /// </summary>
        public bool AllowSelfSignedCerts { get; set; } = false;

        /// <summary>
        /// Gets or sets the maximum certificate age in days.
        /// </summary>
        public int CertificateValidityDays { get; set; } = 365;

        /// <summary>
        /// Gets or sets the list of trusted certificate authorities.
        /// </summary>
        public List<string> TrustedCertificateAuthorities { get; set; } = new();

        /// <summary>
        /// Gets or sets whether OCSP validation is required.
        /// </summary>
        public bool RequireOcspValidation { get; set; } = true;

        /// <summary>
        /// Gets or sets whether CRL checking is required.
        /// </summary>
        public bool RequireCrlChecking { get; set; } = true;
    }

    /// <summary>
    /// Represents the result of a policy evaluation.
    /// </summary>
    public class PolicyEvaluationResult
    {
        /// <summary>
        /// Gets or sets the effective algorithm configuration.
        /// </summary>
        public AlgorithmConfiguration EffectiveConfiguration { get; set; } = AlgorithmConfiguration.CreateDefault();

        /// <summary>
        /// Gets or sets whether encryption is required.
        /// </summary>
        public bool RequireEncryption { get; set; } = true;

        /// <summary>
        /// Gets or sets whether unencrypted fallback is allowed.
        /// </summary>
        public bool AllowUnencryptedFallback { get; set; } = false;

        /// <summary>
        /// Gets or sets the applied policies in order of precedence.
        /// </summary>
        public List<AppliedPolicy> AppliedPolicies { get; set; } = new();

        /// <summary>
        /// Gets or sets any policy violations detected.
        /// </summary>
        public List<PolicyViolation> Violations { get; set; } = new();

        /// <summary>
        /// Gets or sets the evaluation timestamp.
        /// </summary>
        public DateTime EvaluatedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Gets or sets additional context information.
        /// </summary>
        public Dictionary<string, object> Context { get; set; } = new();
    }

    /// <summary>
    /// Represents an applied policy with its source and precedence.
    /// </summary>
    public class AppliedPolicy
    {
        /// <summary>
        /// Gets or sets the policy source.
        /// </summary>
        public PolicySource Source { get; set; }

        /// <summary>
        /// Gets or sets the policy description.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the policy precedence level.
        /// </summary>
        public int Precedence { get; set; }

        /// <summary>
        /// Gets or sets the settings applied by this policy.
        /// </summary>
        public Dictionary<string, object> Settings { get; set; } = new();
    }

    /// <summary>
    /// Represents a policy violation.
    /// </summary>
    public class PolicyViolation
    {
        /// <summary>
        /// Gets or sets the violation type.
        /// </summary>
        public ViolationType Type { get; set; }

        /// <summary>
        /// Gets or sets the violation severity.
        /// </summary>
        public ViolationSeverity Severity { get; set; }

        /// <summary>
        /// Gets or sets the violation message.
        /// </summary>
        public string Message { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the policy setting that was violated.
        /// </summary>
        public string PolicySetting { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the attempted value that caused the violation.
        /// </summary>
        public object? AttemptedValue { get; set; }

        /// <summary>
        /// Gets or sets the required/expected value.
        /// </summary>
        public object? ExpectedValue { get; set; }
    }

    #region Enums

    /// <summary>
    /// Defines the source of a policy configuration.
    /// </summary>
    public enum PolicySource
    {
        Default = 0,
        Configuration = 1,
        Registry = 2,
        GroupPolicy = 3,
        UserOverride = 4,
        DomainOverride = 5,
        RecipientOverride = 6
    }

    /// <summary>
    /// Defines security levels for cryptographic operations.
    /// </summary>
    public enum SecurityLevel
    {
        Low = 1,
        Standard = 2,
        High = 3,
        Critical = 4
    }

    /// <summary>
    /// Defines policy override modes.
    /// </summary>
    public enum OverrideMode
    {
        Strict = 0,
        Balanced = 1,
        Permissive = 2
    }

    /// <summary>
    /// Defines logging levels.
    /// </summary>
    public enum LogLevel
    {
        Error = 0,
        Warning = 1,
        Information = 2,
        Debug = 3
    }

    /// <summary>
    /// Defines violation types.
    /// </summary>
    public enum ViolationType
    {
        SecurityViolation,
        PolicyOverride,
        AlgorithmRestriction,
        ConfigurationError,
        CertificateValidation
    }

    /// <summary>
    /// Defines violation severities.
    /// </summary>
    public enum ViolationSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    #endregion
}