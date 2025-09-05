using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Cryptography
{
    /// <summary>
    /// Implementation of the hybrid encryption engine that combines PQC and classical algorithms.
    /// </summary>
    public class HybridEncryptionEngine : IHybridEncryptionEngine
    {
        private readonly ICryptographicProvider _cryptographicProvider;
        private readonly ILogger<HybridEncryptionEngine> _logger;
        private readonly RandomNumberGenerator _rng;

        /// <summary>
        /// Initializes a new instance of the <see cref="HybridEncryptionEngine"/> class.
        /// </summary>
        /// <param name="cryptographicProvider">The cryptographic provider</param>
        /// <param name="logger">The logger instance</param>
        public HybridEncryptionEngine(ICryptographicProvider cryptographicProvider, ILogger<HybridEncryptionEngine> logger)
        {
            _cryptographicProvider = cryptographicProvider ?? throw new ArgumentNullException(nameof(cryptographicProvider));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _rng = RandomNumberGenerator.Create();
        }

        /// <summary>
        /// Encrypts data using hybrid encryption (PQC + classical).
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="pqcPublicKey">The post-quantum public key</param>
        /// <param name="classicalPublicKey">The classical public key</param>
        /// <returns>A task that represents the asynchronous hybrid encryption operation</returns>
        public async Task<CryptographicResult<HybridEncryptionResult>> EncryptHybridAsync(
            byte[] data, 
            byte[] pqcPublicKey, 
            byte[] classicalPublicKey)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));

            try
            {
                _logger.LogDebug("Starting hybrid encryption operation for {DataSize} bytes", data.Length);

                // Generate a random symmetric key for data encryption
                var symmetricKey = new byte[32]; // 256-bit key for AES-256
                _rng.GetBytes(symmetricKey);

                // Generate IV for AES-GCM
                var iv = new byte[12]; // 96-bit IV for GCM
                _rng.GetBytes(iv);

                // Encrypt the data with AES-256-GCM
                var (encryptedData, authTag) = await EncryptWithAesGcmAsync(data, symmetricKey, iv);

                byte[]? pqcEncryptedKey = null;
                byte[]? classicalEncryptedKey = null;
                string? pqcAlgorithm = null;
                string? classicalAlgorithm = null;

                var strategy = EncryptionStrategy.Hybrid;

                // Encrypt symmetric key with PQC algorithm if available
                if (pqcPublicKey != null && _cryptographicProvider.Configuration.Mode != CryptographicMode.ClassicalOnly)
                {
                    var pqcResult = await _cryptographicProvider.EncryptAsync(symmetricKey, pqcPublicKey);
                    if (pqcResult.IsSuccess)
                    {
                        pqcEncryptedKey = pqcResult.Data!.EncryptedData;
                        pqcAlgorithm = pqcResult.Data.Algorithm;
                        _logger.LogDebug("Successfully encrypted symmetric key with PQC algorithm: {Algorithm}", pqcAlgorithm);
                    }
                    else
                    {
                        _logger.LogWarning("PQC encryption failed: {Error}", pqcResult.ErrorMessage);
                    }
                }

                // Encrypt symmetric key with classical algorithm if available
                if (classicalPublicKey != null && _cryptographicProvider.Configuration.Mode != CryptographicMode.PostQuantumOnly)
                {
                    var classicalResult = await _cryptographicProvider.EncryptAsync(symmetricKey, classicalPublicKey);
                    if (classicalResult.IsSuccess)
                    {
                        classicalEncryptedKey = classicalResult.Data!.EncryptedData;
                        classicalAlgorithm = classicalResult.Data.Algorithm;
                        _logger.LogDebug("Successfully encrypted symmetric key with classical algorithm: {Algorithm}", classicalAlgorithm);
                    }
                    else
                    {
                        _logger.LogWarning("Classical encryption failed: {Error}", classicalResult.ErrorMessage);
                    }
                }

                // Determine the actual strategy based on what succeeded
                if (pqcEncryptedKey != null && classicalEncryptedKey != null)
                {
                    strategy = EncryptionStrategy.Hybrid;
                }
                else if (pqcEncryptedKey != null)
                {
                    strategy = EncryptionStrategy.PostQuantumOnly;
                }
                else if (classicalEncryptedKey != null)
                {
                    strategy = EncryptionStrategy.ClassicalOnly;
                }
                else
                {
                    return CryptographicResult<HybridEncryptionResult>.Failure("Failed to encrypt with any available algorithm");
                }

                // Create algorithm info
                var algorithmInfo = new HybridAlgorithmInfo(pqcAlgorithm, classicalAlgorithm, "AES-256-GCM");

                // Create hybrid encrypted data
                var hybridEncryptedData = new HybridEncryptedData(
                    pqcEncryptedKey,
                    classicalEncryptedKey,
                    encryptedData,
                    iv,
                    authTag,
                    algorithmInfo);

                // Create metadata
                var metadata = new EncryptionMetadata(
                    timestamp: DateTime.UtcNow,
                    isPostQuantum: pqcEncryptedKey != null,
                    isHybrid: strategy == EncryptionStrategy.Hybrid,
                    classicalAlgorithm: classicalAlgorithm,
                    postQuantumAlgorithm: pqcAlgorithm);

                var result = new HybridEncryptionResult(hybridEncryptedData, strategy, metadata);
                _logger.LogInformation("Hybrid encryption completed successfully with strategy: {Strategy}", strategy);

                return CryptographicResult<HybridEncryptionResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Hybrid encryption operation failed");
                return CryptographicResult<HybridEncryptionResult>.Failure("Hybrid encryption failed", ex);
            }
        }

        /// <summary>
        /// Decrypts data that was encrypted using hybrid encryption.
        /// </summary>
        /// <param name="hybridEncryptedData">The hybrid encrypted data</param>
        /// <param name="pqcPrivateKey">The post-quantum private key</param>
        /// <param name="classicalPrivateKey">The classical private key</param>
        /// <returns>A task that represents the asynchronous hybrid decryption operation</returns>
        public async Task<CryptographicResult<byte[]>> DecryptHybridAsync(
            HybridEncryptedData hybridEncryptedData,
            byte[] pqcPrivateKey,
            byte[] classicalPrivateKey)
        {
            if (hybridEncryptedData == null) throw new ArgumentNullException(nameof(hybridEncryptedData));

            try
            {
                _logger.LogDebug("Starting hybrid decryption operation");

                byte[]? symmetricKey = null;

                // Try to decrypt with PQC algorithm first
                if (hybridEncryptedData.PostQuantumEncryptedKey != null && pqcPrivateKey != null)
                {
                    var pqcResult = await _cryptographicProvider.DecryptAsync(hybridEncryptedData.PostQuantumEncryptedKey, pqcPrivateKey);
                    if (pqcResult.IsSuccess)
                    {
                        symmetricKey = pqcResult.Data;
                        _logger.LogDebug("Successfully decrypted symmetric key with PQC algorithm");
                    }
                    else
                    {
                        _logger.LogWarning("PQC decryption failed: {Error}", pqcResult.ErrorMessage);
                    }
                }

                // Fall back to classical algorithm if PQC failed or is not available
                if (symmetricKey == null && hybridEncryptedData.ClassicalEncryptedKey != null && classicalPrivateKey != null)
                {
                    var classicalResult = await _cryptographicProvider.DecryptAsync(hybridEncryptedData.ClassicalEncryptedKey, classicalPrivateKey);
                    if (classicalResult.IsSuccess)
                    {
                        symmetricKey = classicalResult.Data;
                        _logger.LogDebug("Successfully decrypted symmetric key with classical algorithm");
                    }
                    else
                    {
                        _logger.LogWarning("Classical decryption failed: {Error}", classicalResult.ErrorMessage);
                    }
                }

                if (symmetricKey == null)
                {
                    return CryptographicResult<byte[]>.Failure("Failed to decrypt symmetric key with any available algorithm");
                }

                // Decrypt the data with AES-256-GCM
                var decryptedData = await DecryptWithAesGcmAsync(
                    hybridEncryptedData.SymmetricEncryptedData,
                    symmetricKey,
                    hybridEncryptedData.InitializationVector,
                    hybridEncryptedData.AuthenticationTag);

                _logger.LogInformation("Hybrid decryption completed successfully");
                return CryptographicResult<byte[]>.Success(decryptedData);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Hybrid decryption operation failed");
                return CryptographicResult<byte[]>.Failure("Hybrid decryption failed", ex);
            }
        }

        /// <summary>
        /// Determines the optimal encryption strategy based on recipient capabilities.
        /// </summary>
        /// <param name="recipientCapabilities">The recipient's cryptographic capabilities</param>
        /// <returns>The recommended encryption strategy</returns>
        public EncryptionStrategy DetermineEncryptionStrategy(RecipientCapabilities recipientCapabilities)
        {
            if (recipientCapabilities == null) throw new ArgumentNullException(nameof(recipientCapabilities));

            _logger.LogDebug("Determining encryption strategy for recipient with PQC support: {SupportsPostQuantum}, Hybrid support: {SupportsHybrid}",
                recipientCapabilities.SupportsPostQuantum, recipientCapabilities.SupportsHybrid);

            // If we're in PQC-only mode, use PQC regardless of recipient capabilities
            if (_cryptographicProvider.Configuration.Mode == CryptographicMode.PostQuantumOnly)
            {
                if (recipientCapabilities.SupportsPostQuantum)
                {
                    return EncryptionStrategy.PostQuantumOnly;
                }
                else
                {
                    _logger.LogWarning("Recipient doesn't support PQC but provider is in PQC-only mode");
                    return EncryptionStrategy.PostQuantumOnly; // Still try PQC-only
                }
            }

            // If we're in classical-only mode, use classical only
            if (_cryptographicProvider.Configuration.Mode == CryptographicMode.ClassicalOnly)
            {
                return EncryptionStrategy.ClassicalOnly;
            }

            // We're in hybrid mode - determine the best strategy
            if (recipientCapabilities.SupportsHybrid)
            {
                return EncryptionStrategy.Hybrid;
            }
            else if (recipientCapabilities.SupportsPostQuantum)
            {
                // Check if recipient supports our preferred PQC algorithms
                var supportsPqcKem = Array.Exists(recipientCapabilities.SupportedPqcKemAlgorithms, 
                    alg => alg == _cryptographicProvider.Configuration.PreferredKemAlgorithm);
                
                if (supportsPqcKem)
                {
                    return EncryptionStrategy.PostQuantumOnly;
                }
            }

            // Fall back to classical if recipient doesn't support our PQC algorithms
            return EncryptionStrategy.ClassicalOnly;
        }

        #region Private Methods

        private async Task<(byte[] encryptedData, byte[] authTag)> EncryptWithAesGcmAsync(byte[] data, byte[] key, byte[] iv)
        {
            using (var aes = new AesGcm(key))
            {
                var encryptedData = new byte[data.Length];
                var authTag = new byte[16]; // 128-bit authentication tag
                
                aes.Encrypt(iv, data, encryptedData, authTag);
                
                return (encryptedData, authTag);
            }
        }

        private async Task<byte[]> DecryptWithAesGcmAsync(byte[] encryptedData, byte[] key, byte[] iv, byte[] authTag)
        {
            using (var aes = new AesGcm(key))
            {
                var decryptedData = new byte[encryptedData.Length];
                
                aes.Decrypt(iv, encryptedData, authTag, decryptedData);
                
                return decryptedData;
            }
        }

        #endregion
    }
}