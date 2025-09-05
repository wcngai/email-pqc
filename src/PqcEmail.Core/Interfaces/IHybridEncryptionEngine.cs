using System.Threading.Tasks;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Interfaces
{
    /// <summary>
    /// Defines the contract for a hybrid encryption engine that combines PQC and classical algorithms.
    /// </summary>
    public interface IHybridEncryptionEngine
    {
        /// <summary>
        /// Encrypts data using hybrid encryption (PQC + classical).
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="pqcPublicKey">The post-quantum public key</param>
        /// <param name="classicalPublicKey">The classical public key</param>
        /// <returns>A task that represents the asynchronous hybrid encryption operation</returns>
        Task<CryptographicResult<HybridEncryptionResult>> EncryptHybridAsync(
            byte[] data, 
            byte[] pqcPublicKey, 
            byte[] classicalPublicKey);

        /// <summary>
        /// Decrypts data that was encrypted using hybrid encryption.
        /// </summary>
        /// <param name="hybridEncryptedData">The hybrid encrypted data</param>
        /// <param name="pqcPrivateKey">The post-quantum private key</param>
        /// <param name="classicalPrivateKey">The classical private key</param>
        /// <returns>A task that represents the asynchronous hybrid decryption operation</returns>
        Task<CryptographicResult<byte[]>> DecryptHybridAsync(
            HybridEncryptedData hybridEncryptedData,
            byte[] pqcPrivateKey,
            byte[] classicalPrivateKey);

        /// <summary>
        /// Determines the optimal encryption strategy based on recipient capabilities.
        /// </summary>
        /// <param name="recipientCapabilities">The recipient's cryptographic capabilities</param>
        /// <returns>The recommended encryption strategy</returns>
        EncryptionStrategy DetermineEncryptionStrategy(RecipientCapabilities recipientCapabilities);
    }

    /// <summary>
    /// Represents the result of a hybrid encryption operation.
    /// </summary>
    public class HybridEncryptionResult
    {
        /// <summary>
        /// Gets the hybrid encrypted data.
        /// </summary>
        public HybridEncryptedData EncryptedData { get; }

        /// <summary>
        /// Gets the encryption strategy that was used.
        /// </summary>
        public EncryptionStrategy Strategy { get; }

        /// <summary>
        /// Gets metadata about the hybrid encryption operation.
        /// </summary>
        public EncryptionMetadata Metadata { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HybridEncryptionResult"/> class.
        /// </summary>
        /// <param name="encryptedData">The hybrid encrypted data</param>
        /// <param name="strategy">The encryption strategy that was used</param>
        /// <param name="metadata">Metadata about the encryption operation</param>
        public HybridEncryptionResult(HybridEncryptedData encryptedData, EncryptionStrategy strategy, EncryptionMetadata metadata)
        {
            EncryptedData = encryptedData;
            Strategy = strategy;
            Metadata = metadata;
        }
    }

    /// <summary>
    /// Represents hybrid encrypted data containing both PQC and classical components.
    /// </summary>
    public class HybridEncryptedData
    {
        /// <summary>
        /// Gets the post-quantum encrypted key material.
        /// </summary>
        public byte[]? PostQuantumEncryptedKey { get; }

        /// <summary>
        /// Gets the classical encrypted key material.
        /// </summary>
        public byte[]? ClassicalEncryptedKey { get; }

        /// <summary>
        /// Gets the symmetrically encrypted data.
        /// </summary>
        public byte[] SymmetricEncryptedData { get; }

        /// <summary>
        /// Gets the initialization vector used for symmetric encryption.
        /// </summary>
        public byte[] InitializationVector { get; }

        /// <summary>
        /// Gets the authentication tag for the symmetric encryption.
        /// </summary>
        public byte[] AuthenticationTag { get; }

        /// <summary>
        /// Gets the algorithm identifiers used.
        /// </summary>
        public HybridAlgorithmInfo AlgorithmInfo { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HybridEncryptedData"/> class.
        /// </summary>
        /// <param name="postQuantumEncryptedKey">The post-quantum encrypted key material</param>
        /// <param name="classicalEncryptedKey">The classical encrypted key material</param>
        /// <param name="symmetricEncryptedData">The symmetrically encrypted data</param>
        /// <param name="initializationVector">The initialization vector</param>
        /// <param name="authenticationTag">The authentication tag</param>
        /// <param name="algorithmInfo">The algorithm information</param>
        public HybridEncryptedData(
            byte[]? postQuantumEncryptedKey,
            byte[]? classicalEncryptedKey,
            byte[] symmetricEncryptedData,
            byte[] initializationVector,
            byte[] authenticationTag,
            HybridAlgorithmInfo algorithmInfo)
        {
            PostQuantumEncryptedKey = postQuantumEncryptedKey;
            ClassicalEncryptedKey = classicalEncryptedKey;
            SymmetricEncryptedData = symmetricEncryptedData;
            InitializationVector = initializationVector;
            AuthenticationTag = authenticationTag;
            AlgorithmInfo = algorithmInfo;
        }
    }

    /// <summary>
    /// Contains algorithm information for hybrid encryption.
    /// </summary>
    public class HybridAlgorithmInfo
    {
        /// <summary>
        /// Gets the post-quantum key encapsulation mechanism algorithm.
        /// </summary>
        public string? PostQuantumKemAlgorithm { get; }

        /// <summary>
        /// Gets the classical key encapsulation mechanism algorithm.
        /// </summary>
        public string? ClassicalKemAlgorithm { get; }

        /// <summary>
        /// Gets the symmetric encryption algorithm.
        /// </summary>
        public string SymmetricAlgorithm { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="HybridAlgorithmInfo"/> class.
        /// </summary>
        /// <param name="postQuantumKemAlgorithm">The post-quantum KEM algorithm</param>
        /// <param name="classicalKemAlgorithm">The classical KEM algorithm</param>
        /// <param name="symmetricAlgorithm">The symmetric algorithm</param>
        public HybridAlgorithmInfo(string? postQuantumKemAlgorithm, string? classicalKemAlgorithm, string symmetricAlgorithm)
        {
            PostQuantumKemAlgorithm = postQuantumKemAlgorithm;
            ClassicalKemAlgorithm = classicalKemAlgorithm;
            SymmetricAlgorithm = symmetricAlgorithm;
        }
    }

    /// <summary>
    /// Represents the capabilities of a recipient for cryptographic operations.
    /// </summary>
    public class RecipientCapabilities
    {
        /// <summary>
        /// Gets a value indicating whether the recipient supports post-quantum cryptography.
        /// </summary>
        public bool SupportsPostQuantum { get; }

        /// <summary>
        /// Gets the supported post-quantum KEM algorithms.
        /// </summary>
        public string[] SupportedPqcKemAlgorithms { get; }

        /// <summary>
        /// Gets the supported post-quantum signature algorithms.
        /// </summary>
        public string[] SupportedPqcSignatureAlgorithms { get; }

        /// <summary>
        /// Gets the supported classical algorithms.
        /// </summary>
        public string[] SupportedClassicalAlgorithms { get; }

        /// <summary>
        /// Gets a value indicating whether the recipient supports hybrid mode.
        /// </summary>
        public bool SupportsHybrid { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="RecipientCapabilities"/> class.
        /// </summary>
        /// <param name="supportsPostQuantum">Whether the recipient supports post-quantum cryptography</param>
        /// <param name="supportedPqcKemAlgorithms">The supported post-quantum KEM algorithms</param>
        /// <param name="supportedPqcSignatureAlgorithms">The supported post-quantum signature algorithms</param>
        /// <param name="supportedClassicalAlgorithms">The supported classical algorithms</param>
        /// <param name="supportsHybrid">Whether the recipient supports hybrid mode</param>
        public RecipientCapabilities(
            bool supportsPostQuantum,
            string[] supportedPqcKemAlgorithms,
            string[] supportedPqcSignatureAlgorithms,
            string[] supportedClassicalAlgorithms,
            bool supportsHybrid)
        {
            SupportsPostQuantum = supportsPostQuantum;
            SupportedPqcKemAlgorithms = supportedPqcKemAlgorithms ?? new string[0];
            SupportedPqcSignatureAlgorithms = supportedPqcSignatureAlgorithms ?? new string[0];
            SupportedClassicalAlgorithms = supportedClassicalAlgorithms ?? new string[0];
            SupportsHybrid = supportsHybrid;
        }
    }

    /// <summary>
    /// Defines the encryption strategies available.
    /// </summary>
    public enum EncryptionStrategy
    {
        /// <summary>
        /// Use classical algorithms only.
        /// </summary>
        ClassicalOnly,

        /// <summary>
        /// Use post-quantum algorithms only.
        /// </summary>
        PostQuantumOnly,

        /// <summary>
        /// Use hybrid approach with both PQC and classical algorithms.
        /// </summary>
        Hybrid,

        /// <summary>
        /// Automatically determine the best strategy based on recipient capabilities.
        /// </summary>
        Auto
    }
}