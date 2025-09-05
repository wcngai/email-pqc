using System;
using System.Threading.Tasks;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Interfaces
{
    /// <summary>
    /// Defines the contract for cryptographic operations supporting both classical and post-quantum algorithms.
    /// </summary>
    public interface ICryptographicProvider
    {
        /// <summary>
        /// Gets the current algorithm configuration.
        /// </summary>
        AlgorithmConfiguration Configuration { get; }

        /// <summary>
        /// Encrypts data using the configured encryption algorithms.
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="recipientPublicKey">The recipient's public key for key encapsulation</param>
        /// <returns>A task that represents the asynchronous encryption operation</returns>
        Task<CryptographicResult<EncryptionResult>> EncryptAsync(byte[] data, byte[] recipientPublicKey);

        /// <summary>
        /// Decrypts data using the configured decryption algorithms.
        /// </summary>
        /// <param name="encryptedData">The encrypted data to decrypt</param>
        /// <param name="privateKey">The private key for decryption</param>
        /// <returns>A task that represents the asynchronous decryption operation</returns>
        Task<CryptographicResult<byte[]>> DecryptAsync(byte[] encryptedData, byte[] privateKey);

        /// <summary>
        /// Signs data using the configured signature algorithms.
        /// </summary>
        /// <param name="data">The data to sign</param>
        /// <param name="signingPrivateKey">The private key for signing</param>
        /// <returns>A task that represents the asynchronous signing operation</returns>
        Task<CryptographicResult<SignatureResult>> SignAsync(byte[] data, byte[] signingPrivateKey);

        /// <summary>
        /// Verifies a signature using the configured signature algorithms.
        /// </summary>
        /// <param name="data">The original data that was signed</param>
        /// <param name="signature">The signature to verify</param>
        /// <param name="signingPublicKey">The public key for verification</param>
        /// <returns>A task that represents the asynchronous verification operation</returns>
        Task<CryptographicResult<bool>> VerifySignatureAsync(byte[] data, byte[] signature, byte[] signingPublicKey);

        /// <summary>
        /// Generates a new key pair for the specified algorithm.
        /// </summary>
        /// <param name="algorithmName">The name of the algorithm</param>
        /// <param name="isForSigning">Whether this key pair is for signing (true) or encryption (false)</param>
        /// <returns>A task that represents the asynchronous key generation operation</returns>
        Task<CryptographicResult<KeyPair>> GenerateKeyPairAsync(string algorithmName, bool isForSigning);

        /// <summary>
        /// Checks if the specified algorithm is available.
        /// </summary>
        /// <param name="algorithmName">The name of the algorithm to check</param>
        /// <returns>True if the algorithm is available, false otherwise</returns>
        bool IsAlgorithmSupported(string algorithmName);

        /// <summary>
        /// Gets performance metrics for the last operation.
        /// </summary>
        /// <returns>Performance metrics or null if no operation has been performed</returns>
        PerformanceMetrics? GetLastOperationMetrics();
    }

    /// <summary>
    /// Represents a cryptographic key pair.
    /// </summary>
    public class KeyPair
    {
        /// <summary>
        /// Gets the public key.
        /// </summary>
        public byte[] PublicKey { get; }

        /// <summary>
        /// Gets the private key.
        /// </summary>
        public byte[] PrivateKey { get; }

        /// <summary>
        /// Gets the algorithm name used to generate this key pair.
        /// </summary>
        public string Algorithm { get; }

        /// <summary>
        /// Gets a value indicating whether this key pair is intended for signing.
        /// </summary>
        public bool IsForSigning { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="KeyPair"/> class.
        /// </summary>
        /// <param name="publicKey">The public key</param>
        /// <param name="privateKey">The private key</param>
        /// <param name="algorithm">The algorithm used to generate the key pair</param>
        /// <param name="isForSigning">Whether this key pair is for signing</param>
        public KeyPair(byte[] publicKey, byte[] privateKey, string algorithm, bool isForSigning)
        {
            PublicKey = publicKey ?? throw new ArgumentNullException(nameof(publicKey));
            PrivateKey = privateKey ?? throw new ArgumentNullException(nameof(privateKey));
            Algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            IsForSigning = isForSigning;
        }
    }

    /// <summary>
    /// Contains performance metrics for cryptographic operations.
    /// </summary>
    public class PerformanceMetrics
    {
        /// <summary>
        /// Gets the operation that was performed.
        /// </summary>
        public string Operation { get; }

        /// <summary>
        /// Gets the algorithm that was used.
        /// </summary>
        public string Algorithm { get; }

        /// <summary>
        /// Gets the time taken for the operation.
        /// </summary>
        public TimeSpan Duration { get; }

        /// <summary>
        /// Gets the size of the input data in bytes.
        /// </summary>
        public long InputSize { get; }

        /// <summary>
        /// Gets the size of the output data in bytes.
        /// </summary>
        public long OutputSize { get; }

        /// <summary>
        /// Gets the timestamp when the operation was performed.
        /// </summary>
        public DateTime Timestamp { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="PerformanceMetrics"/> class.
        /// </summary>
        /// <param name="operation">The operation that was performed</param>
        /// <param name="algorithm">The algorithm that was used</param>
        /// <param name="duration">The time taken for the operation</param>
        /// <param name="inputSize">The size of the input data in bytes</param>
        /// <param name="outputSize">The size of the output data in bytes</param>
        /// <param name="timestamp">The timestamp when the operation was performed</param>
        public PerformanceMetrics(string operation, string algorithm, TimeSpan duration, 
            long inputSize, long outputSize, DateTime timestamp)
        {
            Operation = operation ?? throw new ArgumentNullException(nameof(operation));
            Algorithm = algorithm ?? throw new ArgumentNullException(nameof(algorithm));
            Duration = duration;
            InputSize = inputSize;
            OutputSize = outputSize;
            Timestamp = timestamp;
        }
    }
}