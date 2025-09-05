using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.Tasks;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Interfaces
{
    /// <summary>
    /// Interface for Hardware Security Module (HSM) operations via PKCS#11
    /// </summary>
    public interface IHsmProvider
    {
        /// <summary>
        /// Initializes the HSM connection with PKCS#11 library
        /// </summary>
        /// <param name="libraryPath">Path to PKCS#11 library</param>
        /// <param name="tokenLabel">HSM token label</param>
        /// <returns>True if initialization successful</returns>
        Task<bool> InitializeAsync(string libraryPath, string tokenLabel);

        /// <summary>
        /// Authenticates with the HSM token
        /// </summary>
        /// <param name="pin">User PIN for authentication</param>
        /// <param name="authMethod">Authentication method</param>
        /// <returns>Authentication result</returns>
        Task<HsmAuthenticationResult> AuthenticateAsync(string pin, HsmAuthMethod authMethod = HsmAuthMethod.Pin);

        /// <summary>
        /// Lists all available HSM tokens
        /// </summary>
        /// <returns>Collection of available tokens</returns>
        Task<IEnumerable<HsmTokenInfo>> ListTokensAsync();

        /// <summary>
        /// Generates a keypair directly in the HSM
        /// </summary>
        /// <param name="algorithm">Cryptographic algorithm</param>
        /// <param name="keySize">Key size in bits</param>
        /// <param name="keyLabel">Key object label in HSM</param>
        /// <param name="usage">Key usage flags</param>
        /// <returns>HSM key pair information</returns>
        Task<HsmKeyPairInfo> GenerateKeyPairAsync(string algorithm, int keySize, string keyLabel, KeyUsage usage);

        /// <summary>
        /// Stores an existing keypair in the HSM
        /// </summary>
        /// <param name="keyPair">Keypair to store</param>
        /// <param name="keyLabel">Key object label in HSM</param>
        /// <returns>Storage operation result</returns>
        Task<HsmStorageResult> StoreKeyPairAsync(KeyPairInfo keyPair, string keyLabel);

        /// <summary>
        /// Retrieves a keypair from the HSM
        /// </summary>
        /// <param name="keyLabel">Key object label</param>
        /// <returns>Retrieved keypair or null if not found</returns>
        Task<HsmKeyPairInfo?> RetrieveKeyPairAsync(string keyLabel);

        /// <summary>
        /// Deletes a keypair from the HSM
        /// </summary>
        /// <param name="keyLabel">Key object label</param>
        /// <returns>True if deletion successful</returns>
        Task<bool> DeleteKeyPairAsync(string keyLabel);

        /// <summary>
        /// Lists all keypairs stored in the HSM
        /// </summary>
        /// <returns>Collection of HSM keypair information</returns>
        Task<IEnumerable<HsmKeyPairInfo>> ListKeyPairsAsync();

        /// <summary>
        /// Performs cryptographic signing operation using HSM-stored key
        /// </summary>
        /// <param name="keyLabel">Signing key label</param>
        /// <param name="data">Data to sign</param>
        /// <param name="hashAlgorithm">Hash algorithm to use</param>
        /// <returns>Digital signature</returns>
        Task<byte[]> SignAsync(string keyLabel, byte[] data, HashAlgorithmName hashAlgorithm);

        /// <summary>
        /// Verifies a digital signature using HSM-stored public key
        /// </summary>
        /// <param name="keyLabel">Verification key label</param>
        /// <param name="data">Original data</param>
        /// <param name="signature">Signature to verify</param>
        /// <param name="hashAlgorithm">Hash algorithm used</param>
        /// <returns>True if signature is valid</returns>
        Task<bool> VerifySignatureAsync(string keyLabel, byte[] data, byte[] signature, HashAlgorithmName hashAlgorithm);

        /// <summary>
        /// Performs key encapsulation (for PQC KEM algorithms)
        /// </summary>
        /// <param name="keyLabel">Encapsulation key label</param>
        /// <param name="sharedSecretLength">Desired shared secret length</param>
        /// <returns>Encapsulation result with ciphertext and shared secret</returns>
        Task<HsmEncapsulationResult> EncapsulateAsync(string keyLabel, int sharedSecretLength);

        /// <summary>
        /// Performs key decapsulation (for PQC KEM algorithms)
        /// </summary>
        /// <param name="keyLabel">Decapsulation key label</param>
        /// <param name="ciphertext">Encapsulated ciphertext</param>
        /// <returns>Decapsulated shared secret</returns>
        Task<byte[]> DecapsulateAsync(string keyLabel, byte[] ciphertext);

        /// <summary>
        /// Encrypts data using HSM-stored key
        /// </summary>
        /// <param name="keyLabel">Encryption key label</param>
        /// <param name="plaintext">Data to encrypt</param>
        /// <param name="algorithm">Encryption algorithm</param>
        /// <returns>Encrypted data</returns>
        Task<byte[]> EncryptAsync(string keyLabel, byte[] plaintext, string algorithm = "AES-GCM");

        /// <summary>
        /// Decrypts data using HSM-stored key
        /// </summary>
        /// <param name="keyLabel">Decryption key label</param>
        /// <param name="ciphertext">Encrypted data</param>
        /// <param name="algorithm">Encryption algorithm</param>
        /// <returns>Decrypted data</returns>
        Task<byte[]> DecryptAsync(string keyLabel, byte[] ciphertext, string algorithm = "AES-GCM");

        /// <summary>
        /// Gets HSM token information
        /// </summary>
        /// <param name="tokenLabel">Token label</param>
        /// <returns>Token information</returns>
        Task<HsmTokenInfo?> GetTokenInfoAsync(string tokenLabel);

        /// <summary>
        /// Gets HSM mechanism (algorithm) information
        /// </summary>
        /// <param name="mechanismType">Mechanism type</param>
        /// <returns>Mechanism information</returns>
        Task<HsmMechanismInfo?> GetMechanismInfoAsync(string mechanismType);

        /// <summary>
        /// Tests HSM connectivity and functionality
        /// </summary>
        /// <returns>Health check result</returns>
        Task<HsmHealthCheckResult> PerformHealthCheckAsync();

        /// <summary>
        /// Closes the HSM session and releases resources
        /// </summary>
        Task CloseAsync();

        /// <summary>
        /// Gets the current HSM connection status
        /// </summary>
        bool IsConnected { get; }

        /// <summary>
        /// Gets the current HSM token information
        /// </summary>
        HsmTokenInfo? CurrentToken { get; }
    }

    /// <summary>
    /// HSM authentication result
    /// </summary>
    public class HsmAuthenticationResult
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public HsmAuthMethod AuthMethod { get; set; }
        public DateTimeOffset AuthTime { get; set; } = DateTimeOffset.UtcNow;
        public TimeSpan? SessionTimeout { get; set; }

        public static HsmAuthenticationResult Success(HsmAuthMethod authMethod, TimeSpan? sessionTimeout = null)
        {
            return new HsmAuthenticationResult
            {
                Success = true,
                AuthMethod = authMethod,
                SessionTimeout = sessionTimeout
            };
        }

        public static HsmAuthenticationResult Failed(string errorMessage)
        {
            return new HsmAuthenticationResult
            {
                Success = false,
                ErrorMessage = errorMessage
            };
        }
    }

    /// <summary>
    /// HSM token information
    /// </summary>
    public class HsmTokenInfo
    {
        public string Label { get; set; } = string.Empty;
        public string SerialNumber { get; set; } = string.Empty;
        public string ManufacturerID { get; set; } = string.Empty;
        public string Model { get; set; } = string.Empty;
        public string FirmwareVersion { get; set; } = string.Empty;
        public bool IsWriteProtected { get; set; }
        public bool RequiresLogin { get; set; }
        public bool IsInitialized { get; set; }
        public long TotalPublicMemory { get; set; }
        public long FreePublicMemory { get; set; }
        public long TotalPrivateMemory { get; set; }
        public long FreePrivateMemory { get; set; }
        public List<string> SupportedMechanisms { get; set; } = new List<string>();
    }

    /// <summary>
    /// HSM keypair information
    /// </summary>
    public class HsmKeyPairInfo
    {
        public string KeyLabel { get; set; } = string.Empty;
        public string KeyId { get; set; } = string.Empty;
        public string Algorithm { get; set; } = string.Empty;
        public int KeySize { get; set; }
        public KeyUsage Usage { get; set; }
        public bool IsPrivate { get; set; } = true;
        public bool IsExtractable { get; set; } = false;
        public bool IsModifiable { get; set; } = false;
        public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
        public byte[] PublicKeyData { get; set; } = Array.Empty<byte>();
        public Dictionary<string, object> Attributes { get; set; } = new Dictionary<string, object>();
        public HsmTokenInfo? Token { get; set; }
    }

    /// <summary>
    /// HSM storage operation result
    /// </summary>
    public class HsmStorageResult
    {
        public bool Success { get; set; }
        public string? KeyLabel { get; set; }
        public string? KeyId { get; set; }
        public string? ErrorMessage { get; set; }
        public Exception? Exception { get; set; }
        public DateTimeOffset StorageTime { get; set; } = DateTimeOffset.UtcNow;

        public static HsmStorageResult Success(string keyLabel, string keyId)
        {
            return new HsmStorageResult
            {
                Success = true,
                KeyLabel = keyLabel,
                KeyId = keyId
            };
        }

        public static HsmStorageResult Failed(string errorMessage, Exception? exception = null)
        {
            return new HsmStorageResult
            {
                Success = false,
                ErrorMessage = errorMessage,
                Exception = exception
            };
        }
    }

    /// <summary>
    /// HSM key encapsulation result
    /// </summary>
    public class HsmEncapsulationResult
    {
        public byte[] Ciphertext { get; set; } = Array.Empty<byte>();
        public byte[] SharedSecret { get; set; } = Array.Empty<byte>();
        public string Algorithm { get; set; } = string.Empty;
        public Dictionary<string, object> Parameters { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>
    /// HSM mechanism (algorithm) information
    /// </summary>
    public class HsmMechanismInfo
    {
        public string MechanismType { get; set; } = string.Empty;
        public string Name { get; set; } = string.Empty;
        public long MinKeySize { get; set; }
        public long MaxKeySize { get; set; }
        public bool SupportsEncryption { get; set; }
        public bool SupportsDecryption { get; set; }
        public bool SupportsDigest { get; set; }
        public bool SupportsSignature { get; set; }
        public bool SupportsSignatureRecover { get; set; }
        public bool SupportsVerify { get; set; }
        public bool SupportsVerifyRecover { get; set; }
        public bool SupportsGenerate { get; set; }
        public bool SupportsGenerateKeyPair { get; set; }
        public bool SupportsWrap { get; set; }
        public bool SupportsUnwrap { get; set; }
        public bool SupportsDerive { get; set; }
        public Dictionary<string, object> AdditionalInfo { get; set; } = new Dictionary<string, object>();
    }

    /// <summary>
    /// HSM health check result
    /// </summary>
    public class HsmHealthCheckResult
    {
        public bool IsHealthy { get; set; }
        public string Status { get; set; } = string.Empty;
        public List<string> Issues { get; set; } = new List<string>();
        public Dictionary<string, object> Metrics { get; set; } = new Dictionary<string, object>();
        public DateTimeOffset CheckTime { get; set; } = DateTimeOffset.UtcNow;
        public TimeSpan ResponseTime { get; set; }

        public static HsmHealthCheckResult Healthy(TimeSpan responseTime)
        {
            return new HsmHealthCheckResult
            {
                IsHealthy = true,
                Status = "Healthy",
                ResponseTime = responseTime
            };
        }

        public static HsmHealthCheckResult Unhealthy(List<string> issues, TimeSpan responseTime)
        {
            return new HsmHealthCheckResult
            {
                IsHealthy = false,
                Status = "Unhealthy",
                Issues = issues,
                ResponseTime = responseTime
            };
        }
    }
}