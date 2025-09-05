using System;
using System.Collections.Generic;
using System.Security.Cryptography;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Information about a cryptographic keypair including metadata and storage details
    /// </summary>
    public class KeyPairInfo
    {
        /// <summary>
        /// Unique identifier for this keypair
        /// </summary>
        public string KeyId { get; set; } = Guid.NewGuid().ToString();

        /// <summary>
        /// Key container name for Windows CNG storage
        /// </summary>
        public string ContainerName { get; set; } = string.Empty;

        /// <summary>
        /// Identity associated with this keypair (typically email address)
        /// </summary>
        public string Identity { get; set; } = string.Empty;

        /// <summary>
        /// Cryptographic algorithm used
        /// </summary>
        public string Algorithm { get; set; } = string.Empty;

        /// <summary>
        /// Key usage type (signing or encryption)
        /// </summary>
        public KeyUsage Usage { get; set; }

        /// <summary>
        /// Key size in bits/bytes (algorithm-dependent)
        /// </summary>
        public int KeySize { get; set; }

        /// <summary>
        /// When this keypair was created
        /// </summary>
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;

        /// <summary>
        /// When this keypair expires (if applicable)
        /// </summary>
        public DateTimeOffset? ExpiresAt { get; set; }

        /// <summary>
        /// Whether this keypair is stored in HSM
        /// </summary>
        public bool IsHsmBacked { get; set; }

        /// <summary>
        /// HSM token/slot information if applicable
        /// </summary>
        public HsmInfo? HsmInfo { get; set; }

        /// <summary>
        /// Whether this keypair is currently active
        /// </summary>
        public bool IsActive { get; set; } = true;

        /// <summary>
        /// Whether this keypair is archived (for historical decryption)
        /// </summary>
        public bool IsArchived { get; set; }

        /// <summary>
        /// Public key data (for storage/transport)
        /// </summary>
        public byte[] PublicKeyData { get; set; } = Array.Empty<byte>();

        /// <summary>
        /// Public key object (runtime use)
        /// </summary>
        public AsymmetricAlgorithm? PublicKey { get; set; }

        /// <summary>
        /// Private key handle or reference (never the actual key data)
        /// </summary>
        public string? PrivateKeyReference { get; set; }

        /// <summary>
        /// Key generation parameters used
        /// </summary>
        public Dictionary<string, object> GenerationParameters { get; set; } = new Dictionary<string, object>();

        /// <summary>
        /// Additional metadata about this keypair
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new Dictionary<string, object>();

        /// <summary>
        /// Key derivation information if applicable
        /// </summary>
        public KeyDerivationInfo? DerivationInfo { get; set; }

        /// <summary>
        /// Whether this is a PQC keypair
        /// </summary>
        public bool IsPqcKeyPair => Algorithm.StartsWith("ML-") || Algorithm.Contains("Kyber") || Algorithm.Contains("Dilithium");

        /// <summary>
        /// Gets the key fingerprint for identification
        /// </summary>
        public string Fingerprint
        {
            get
            {
                if (PublicKeyData.Length == 0) return string.Empty;
                using var sha256 = System.Security.Cryptography.SHA256.Create();
                var hash = sha256.ComputeHash(PublicKeyData);
                return Convert.ToHexString(hash)[..16]; // First 16 hex chars
            }
        }

        /// <summary>
        /// Checks if keypair is expired
        /// </summary>
        public bool IsExpired => ExpiresAt.HasValue && DateTimeOffset.UtcNow > ExpiresAt.Value;

        /// <summary>
        /// Days until expiration (if applicable)
        /// </summary>
        public int? DaysUntilExpiration
        {
            get
            {
                if (!ExpiresAt.HasValue) return null;
                var days = (ExpiresAt.Value - DateTimeOffset.UtcNow).TotalDays;
                return days > 0 ? (int)Math.Ceiling(days) : 0;
            }
        }

        /// <summary>
        /// Creates a copy of this keypair info for archival
        /// </summary>
        /// <param name="archivalReason">Reason for archival</param>
        /// <returns>Archived copy</returns>
        public KeyPairInfo CreateArchivalCopy(string archivalReason)
        {
            var copy = new KeyPairInfo
            {
                KeyId = Guid.NewGuid().ToString(),
                ContainerName = ContainerName + "_archived_" + DateTimeOffset.UtcNow.Ticks,
                Identity = Identity,
                Algorithm = Algorithm,
                Usage = Usage,
                KeySize = KeySize,
                CreatedAt = CreatedAt,
                ExpiresAt = ExpiresAt,
                IsHsmBacked = IsHsmBacked,
                HsmInfo = HsmInfo,
                IsActive = false,
                IsArchived = true,
                PublicKeyData = PublicKeyData,
                GenerationParameters = new Dictionary<string, object>(GenerationParameters),
                Metadata = new Dictionary<string, object>(Metadata),
                DerivationInfo = DerivationInfo
            };

            copy.Metadata["OriginalKeyId"] = KeyId;
            copy.Metadata["ArchivalReason"] = archivalReason;
            copy.Metadata["ArchivedAt"] = DateTimeOffset.UtcNow;

            return copy;
        }

        /// <summary>
        /// Validates keypair information completeness
        /// </summary>
        /// <returns>Validation result</returns>
        public KeyPairValidationResult Validate()
        {
            var errors = new List<string>();

            if (string.IsNullOrWhiteSpace(ContainerName))
                errors.Add("Container name is required");

            if (string.IsNullOrWhiteSpace(Identity))
                errors.Add("Identity is required");

            if (string.IsNullOrWhiteSpace(Algorithm))
                errors.Add("Algorithm is required");

            if (KeySize <= 0)
                errors.Add("Key size must be positive");

            if (PublicKeyData.Length == 0)
                errors.Add("Public key data is required");

            if (IsActive && IsArchived)
                errors.Add("Keypair cannot be both active and archived");

            return new KeyPairValidationResult
            {
                IsValid = errors.Count == 0,
                Errors = errors
            };
        }
    }

    /// <summary>
    /// HSM (Hardware Security Module) information
    /// </summary>
    public class HsmInfo
    {
        /// <summary>
        /// HSM manufacturer/provider name
        /// </summary>
        public string Provider { get; set; } = string.Empty;

        /// <summary>
        /// HSM token/slot identifier
        /// </summary>
        public string TokenId { get; set; } = string.Empty;

        /// <summary>
        /// PKCS#11 library path
        /// </summary>
        public string? Pkcs11LibraryPath { get; set; }

        /// <summary>
        /// Token authentication PIN/password reference
        /// </summary>
        public string? AuthReference { get; set; }

        /// <summary>
        /// Additional HSM-specific configuration
        /// </summary>
        public Dictionary<string, object> Configuration { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>
    /// Key derivation information
    /// </summary>
    public class KeyDerivationInfo
    {
        /// <summary>
        /// Key derivation function used
        /// </summary>
        public string DerivationFunction { get; set; } = string.Empty;

        /// <summary>
        /// Master key reference
        /// </summary>
        public string? MasterKeyReference { get; set; }

        /// <summary>
        /// Derivation parameters (salt, iterations, etc.)
        /// </summary>
        public Dictionary<string, object> Parameters { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>
    /// Keypair validation result
    /// </summary>
    public class KeyPairValidationResult
    {
        public bool IsValid { get; set; }
        public List<string> Errors { get; set; } = new List<string>();
    }
}