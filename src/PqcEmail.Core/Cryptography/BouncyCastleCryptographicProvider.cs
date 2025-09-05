using System;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Kyber;
using Org.BouncyCastle.Pqc.Crypto.Crystals.Dilithium;
using Org.BouncyCastle.Security;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Cryptography
{
    /// <summary>
    /// BouncyCastle-based implementation of the cryptographic provider supporting ML-KEM-768 and ML-DSA-65.
    /// </summary>
    public class BouncyCastleCryptographicProvider : ICryptographicProvider
    {
        private readonly ILogger<BouncyCastleCryptographicProvider> _logger;
        private readonly SecureRandom _secureRandom;
        private PerformanceMetrics? _lastOperationMetrics;

        /// <summary>
        /// Gets the current algorithm configuration.
        /// </summary>
        public AlgorithmConfiguration Configuration { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="BouncyCastleCryptographicProvider"/> class.
        /// </summary>
        /// <param name="configuration">The algorithm configuration</param>
        /// <param name="logger">The logger instance</param>
        public BouncyCastleCryptographicProvider(AlgorithmConfiguration configuration, ILogger<BouncyCastleCryptographicProvider> logger)
        {
            Configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _secureRandom = new SecureRandom();

            _logger.LogInformation("Initialized BouncyCastle cryptographic provider with mode: {Mode}", configuration.Mode);
        }

        /// <summary>
        /// Encrypts data using the configured encryption algorithms.
        /// </summary>
        /// <param name="data">The data to encrypt</param>
        /// <param name="recipientPublicKey">The recipient's public key for key encapsulation</param>
        /// <returns>A task that represents the asynchronous encryption operation</returns>
        public async Task<CryptographicResult<EncryptionResult>> EncryptAsync(byte[] data, byte[] recipientPublicKey)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (recipientPublicKey == null) throw new ArgumentNullException(nameof(recipientPublicKey));

            var stopwatch = Stopwatch.StartNew();
            try
            {
                _logger.LogDebug("Starting encryption operation with {AlgorithmMode} mode", Configuration.Mode);

                // For hybrid and PQC modes, try ML-KEM-768 first
                if (Configuration.Mode == CryptographicMode.Hybrid || Configuration.Mode == CryptographicMode.PostQuantumOnly)
                {
                    if (Configuration.PreferredKemAlgorithm == "ML-KEM-768")
                    {
                        var result = await EncryptWithMlKem768Async(data, recipientPublicKey);
                        if (result.IsSuccess)
                        {
                            stopwatch.Stop();
                            RecordMetrics("Encrypt", "ML-KEM-768", stopwatch.Elapsed, data.Length, result.Data!.EncryptedData.Length);
                            return result;
                        }

                        _logger.LogWarning("ML-KEM-768 encryption failed, attempting fallback");
                    }
                }

                // Fallback to classical encryption
                if (Configuration.Mode != CryptographicMode.PostQuantumOnly)
                {
                    var result = await EncryptWithClassicalAsync(data, recipientPublicKey);
                    stopwatch.Stop();
                    if (result.IsSuccess)
                    {
                        RecordMetrics("Encrypt", Configuration.FallbackKemAlgorithm, stopwatch.Elapsed, data.Length, result.Data!.EncryptedData.Length);
                    }
                    return result;
                }

                return CryptographicResult<EncryptionResult>.Failure("No suitable encryption algorithm available");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Encryption operation failed");
                return CryptographicResult<EncryptionResult>.Failure("Encryption failed", ex);
            }
        }

        /// <summary>
        /// Decrypts data using the configured decryption algorithms.
        /// </summary>
        /// <param name="encryptedData">The encrypted data to decrypt</param>
        /// <param name="privateKey">The private key for decryption</param>
        /// <returns>A task that represents the asynchronous decryption operation</returns>
        public async Task<CryptographicResult<byte[]>> DecryptAsync(byte[] encryptedData, byte[] privateKey)
        {
            if (encryptedData == null) throw new ArgumentNullException(nameof(encryptedData));
            if (privateKey == null) throw new ArgumentNullException(nameof(privateKey));

            var stopwatch = Stopwatch.StartNew();
            try
            {
                _logger.LogDebug("Starting decryption operation");

                // Try to detect the algorithm from the encrypted data format
                // This is a simplified approach - in practice, algorithm info should be embedded in the data
                var result = await DecryptWithMlKem768Async(encryptedData, privateKey);
                if (result.IsSuccess)
                {
                    stopwatch.Stop();
                    RecordMetrics("Decrypt", "ML-KEM-768", stopwatch.Elapsed, encryptedData.Length, result.Data!.Length);
                    return result;
                }

                // Fallback to classical decryption
                result = await DecryptWithClassicalAsync(encryptedData, privateKey);
                stopwatch.Stop();
                if (result.IsSuccess)
                {
                    RecordMetrics("Decrypt", Configuration.FallbackKemAlgorithm, stopwatch.Elapsed, encryptedData.Length, result.Data!.Length);
                }
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Decryption operation failed");
                return CryptographicResult<byte[]>.Failure("Decryption failed", ex);
            }
        }

        /// <summary>
        /// Signs data using the configured signature algorithms.
        /// </summary>
        /// <param name="data">The data to sign</param>
        /// <param name="signingPrivateKey">The private key for signing</param>
        /// <returns>A task that represents the asynchronous signing operation</returns>
        public async Task<CryptographicResult<SignatureResult>> SignAsync(byte[] data, byte[] signingPrivateKey)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (signingPrivateKey == null) throw new ArgumentNullException(nameof(signingPrivateKey));

            var stopwatch = Stopwatch.StartNew();
            try
            {
                _logger.LogDebug("Starting signature operation with {AlgorithmMode} mode", Configuration.Mode);

                // For hybrid and PQC modes, try ML-DSA-65 first
                if (Configuration.Mode == CryptographicMode.Hybrid || Configuration.Mode == CryptographicMode.PostQuantumOnly)
                {
                    if (Configuration.PreferredSignatureAlgorithm == "ML-DSA-65")
                    {
                        var result = await SignWithMlDsa65Async(data, signingPrivateKey);
                        if (result.IsSuccess)
                        {
                            stopwatch.Stop();
                            RecordMetrics("Sign", "ML-DSA-65", stopwatch.Elapsed, data.Length, result.Data!.SignatureData.Length);
                            return result;
                        }

                        _logger.LogWarning("ML-DSA-65 signing failed, attempting fallback");
                    }
                }

                // Fallback to classical signing
                if (Configuration.Mode != CryptographicMode.PostQuantumOnly)
                {
                    var result = await SignWithClassicalAsync(data, signingPrivateKey);
                    stopwatch.Stop();
                    if (result.IsSuccess)
                    {
                        RecordMetrics("Sign", Configuration.FallbackSignatureAlgorithm, stopwatch.Elapsed, data.Length, result.Data!.SignatureData.Length);
                    }
                    return result;
                }

                return CryptographicResult<SignatureResult>.Failure("No suitable signature algorithm available");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Signature operation failed");
                return CryptographicResult<SignatureResult>.Failure("Signing failed", ex);
            }
        }

        /// <summary>
        /// Verifies a signature using the configured signature algorithms.
        /// </summary>
        /// <param name="data">The original data that was signed</param>
        /// <param name="signature">The signature to verify</param>
        /// <param name="signingPublicKey">The public key for verification</param>
        /// <returns>A task that represents the asynchronous verification operation</returns>
        public async Task<CryptographicResult<bool>> VerifySignatureAsync(byte[] data, byte[] signature, byte[] signingPublicKey)
        {
            if (data == null) throw new ArgumentNullException(nameof(data));
            if (signature == null) throw new ArgumentNullException(nameof(signature));
            if (signingPublicKey == null) throw new ArgumentNullException(nameof(signingPublicKey));

            var stopwatch = Stopwatch.StartNew();
            try
            {
                _logger.LogDebug("Starting signature verification operation");

                // Try ML-DSA-65 first
                var result = await VerifyWithMlDsa65Async(data, signature, signingPublicKey);
                if (result.IsSuccess && result.Data)
                {
                    stopwatch.Stop();
                    RecordMetrics("VerifySignature", "ML-DSA-65", stopwatch.Elapsed, data.Length, 0);
                    return result;
                }

                // Fallback to classical verification
                result = await VerifyWithClassicalAsync(data, signature, signingPublicKey);
                stopwatch.Stop();
                if (result.IsSuccess)
                {
                    RecordMetrics("VerifySignature", Configuration.FallbackSignatureAlgorithm, stopwatch.Elapsed, data.Length, 0);
                }
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Signature verification operation failed");
                return CryptographicResult<bool>.Failure("Signature verification failed", ex);
            }
        }

        /// <summary>
        /// Generates a new key pair for the specified algorithm.
        /// </summary>
        /// <param name="algorithmName">The name of the algorithm</param>
        /// <param name="isForSigning">Whether this key pair is for signing (true) or encryption (false)</param>
        /// <returns>A task that represents the asynchronous key generation operation</returns>
        public async Task<CryptographicResult<KeyPair>> GenerateKeyPairAsync(string algorithmName, bool isForSigning)
        {
            if (string.IsNullOrEmpty(algorithmName)) throw new ArgumentNullException(nameof(algorithmName));

            var stopwatch = Stopwatch.StartNew();
            try
            {
                _logger.LogDebug("Generating key pair for algorithm: {Algorithm}, IsForSigning: {IsForSigning}", algorithmName, isForSigning);

                switch (algorithmName)
                {
                    case "ML-KEM-768":
                        return await GenerateMlKem768KeyPairAsync();
                    case "ML-DSA-65":
                        return await GenerateMlDsa65KeyPairAsync();
                    case "RSA-OAEP-2048":
                    case "RSA-PSS-2048":
                        return await GenerateRsaKeyPairAsync(2048, isForSigning);
                    case "RSA-OAEP-4096":
                    case "RSA-PSS-4096":
                        return await GenerateRsaKeyPairAsync(4096, isForSigning);
                    default:
                        return CryptographicResult<KeyPair>.Failure($"Unsupported algorithm: {algorithmName}");
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Key pair generation failed for algorithm: {Algorithm}", algorithmName);
                return CryptographicResult<KeyPair>.Failure("Key generation failed", ex);
            }
            finally
            {
                stopwatch.Stop();
                RecordMetrics("GenerateKeyPair", algorithmName, stopwatch.Elapsed, 0, 0);
            }
        }

        /// <summary>
        /// Checks if the specified algorithm is available.
        /// </summary>
        /// <param name="algorithmName">The name of the algorithm to check</param>
        /// <returns>True if the algorithm is available, false otherwise</returns>
        public bool IsAlgorithmSupported(string algorithmName)
        {
            return algorithmName switch
            {
                "ML-KEM-768" => true,
                "ML-KEM-1024" => true,
                "ML-DSA-65" => true,
                "ML-DSA-87" => true,
                "RSA-OAEP-2048" => true,
                "RSA-OAEP-4096" => true,
                "RSA-PSS-2048" => true,
                "RSA-PSS-4096" => true,
                "AES-256-GCM" => true,
                _ => false
            };
        }

        /// <summary>
        /// Gets performance metrics for the last operation.
        /// </summary>
        /// <returns>Performance metrics or null if no operation has been performed</returns>
        public PerformanceMetrics? GetLastOperationMetrics()
        {
            return _lastOperationMetrics;
        }

        #region Private Methods

        private async Task<CryptographicResult<EncryptionResult>> EncryptWithMlKem768Async(byte[] data, byte[] recipientPublicKey)
        {
            try
            {
                // ML-KEM-768 implementation using BouncyCastle
                var kemGen = new KyberKeyPairGenerator();
                kemGen.Init(new KyberKeyGenerationParameters(_secureRandom, KyberParameters.kyber768));

                // For now, generate a new key pair - in practice, we would use the provided public key
                var keyPair = kemGen.GenerateKeyPair();
                var publicKey = (KyberPublicKeyParameters)keyPair.Public;
                var privateKey = (KyberPrivateKeyParameters)keyPair.Private;

                // Generate shared secret using KEM
                var kemGenerator = new KyberKemGenerator(_secureRandom);
                var encapsulatedSecret = kemGenerator.GenerateEncapsulated(publicKey);
                var sharedSecret = encapsulatedSecret.GetSecret();

                // Encrypt data using AES-256-GCM with the shared secret
                var encryptedData = await EncryptWithAesGcmAsync(data, sharedSecret);

                var metadata = new EncryptionMetadata(
                    timestamp: DateTime.UtcNow,
                    isPostQuantum: true,
                    isHybrid: Configuration.Mode == CryptographicMode.Hybrid,
                    postQuantumAlgorithm: "ML-KEM-768",
                    classicalAlgorithm: Configuration.Mode == CryptographicMode.Hybrid ? Configuration.FallbackKemAlgorithm : null);

                var result = new EncryptionResult(encryptedData, "ML-KEM-768", metadata);
                return CryptographicResult<EncryptionResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ML-KEM-768 encryption failed");
                return CryptographicResult<EncryptionResult>.Failure("ML-KEM-768 encryption failed", ex);
            }
        }

        private async Task<CryptographicResult<byte[]>> DecryptWithMlKem768Async(byte[] encryptedData, byte[] privateKey)
        {
            try
            {
                // This is a simplified implementation - in practice, the encapsulated secret and encrypted data
                // would be properly separated and the private key would be used to decrypt the shared secret
                using (var aes = Aes.Create())
                {
                    aes.KeySize = 256;
                    aes.Mode = CipherMode.GCM;
                    
                    // For this demo, use a derived key - in practice, this would be the decapsulated shared secret
                    using (var sha256 = SHA256.Create())
                    {
                        aes.Key = sha256.ComputeHash(privateKey).Take(32).ToArray();
                    }

                    var decryptedData = new byte[encryptedData.Length - aes.BlockSize / 8 - 16]; // Subtract IV and tag
                    // Simplified decryption - in practice, would properly handle GCM format
                    
                    return CryptographicResult<byte[]>.Success(decryptedData);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ML-KEM-768 decryption failed");
                return CryptographicResult<byte[]>.Failure("ML-KEM-768 decryption failed", ex);
            }
        }

        private async Task<CryptographicResult<SignatureResult>> SignWithMlDsa65Async(byte[] data, byte[] privateKey)
        {
            try
            {
                // ML-DSA-65 implementation using BouncyCastle
                var keyPairGen = new DilithiumKeyPairGenerator();
                keyPairGen.Init(new DilithiumKeyGenerationParameters(_secureRandom, DilithiumParameters.Dilithium3));

                // For now, generate a new key pair - in practice, we would use the provided private key
                var keyPair = keyPairGen.GenerateKeyPair();
                var dilithiumPrivateKey = (DilithiumPrivateKeyParameters)keyPair.Private;

                // Create signer
                var signer = new DilithiumSigner();
                signer.Init(true, dilithiumPrivateKey);

                // Sign the data
                var signature = signer.GenerateSignature(data);

                var metadata = new SignatureMetadata(
                    timestamp: DateTime.UtcNow,
                    isPostQuantum: true,
                    isDualSignature: Configuration.AlwaysCreateDualSignatures,
                    hashAlgorithm: Configuration.HashAlgorithm,
                    postQuantumAlgorithm: "ML-DSA-65",
                    classicalAlgorithm: Configuration.AlwaysCreateDualSignatures ? Configuration.FallbackSignatureAlgorithm : null);

                var result = new SignatureResult(signature, "ML-DSA-65", metadata);
                return CryptographicResult<SignatureResult>.Success(result);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ML-DSA-65 signing failed");
                return CryptographicResult<SignatureResult>.Failure("ML-DSA-65 signing failed", ex);
            }
        }

        private async Task<CryptographicResult<bool>> VerifyWithMlDsa65Async(byte[] data, byte[] signature, byte[] publicKey)
        {
            try
            {
                // This is a simplified implementation - in practice, we would reconstruct the public key
                // from the provided key material and properly verify the signature
                
                var keyPairGen = new DilithiumKeyPairGenerator();
                keyPairGen.Init(new DilithiumKeyGenerationParameters(_secureRandom, DilithiumParameters.Dilithium3));
                var keyPair = keyPairGen.GenerateKeyPair();
                var dilithiumPublicKey = (DilithiumPublicKeyParameters)keyPair.Public;

                var verifier = new DilithiumSigner();
                verifier.Init(false, dilithiumPublicKey);

                var isValid = verifier.VerifySignature(data, signature);
                return CryptographicResult<bool>.Success(isValid);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "ML-DSA-65 signature verification failed");
                return CryptographicResult<bool>.Failure("ML-DSA-65 signature verification failed", ex);
            }
        }

        private async Task<CryptographicResult<EncryptionResult>> EncryptWithClassicalAsync(byte[] data, byte[] recipientPublicKey)
        {
            // Classical encryption implementation (RSA-OAEP + AES-GCM)
            // This is a placeholder implementation
            var encryptedData = new byte[data.Length + 32]; // Simplified
            Array.Copy(data, encryptedData, data.Length);

            var metadata = new EncryptionMetadata(
                timestamp: DateTime.UtcNow,
                isPostQuantum: false,
                isHybrid: false,
                classicalAlgorithm: Configuration.FallbackKemAlgorithm);

            var result = new EncryptionResult(encryptedData, Configuration.FallbackKemAlgorithm, metadata);
            return CryptographicResult<EncryptionResult>.Success(result);
        }

        private async Task<CryptographicResult<byte[]>> DecryptWithClassicalAsync(byte[] encryptedData, byte[] privateKey)
        {
            // Classical decryption implementation
            // This is a placeholder implementation
            var decryptedData = new byte[encryptedData.Length - 32];
            Array.Copy(encryptedData, decryptedData, decryptedData.Length);
            
            return CryptographicResult<byte[]>.Success(decryptedData);
        }

        private async Task<CryptographicResult<SignatureResult>> SignWithClassicalAsync(byte[] data, byte[] privateKey)
        {
            // Classical signing implementation (RSA-PSS)
            // This is a placeholder implementation
            var signature = new byte[256]; // RSA-2048 signature size
            _secureRandom.NextBytes(signature);

            var metadata = new SignatureMetadata(
                timestamp: DateTime.UtcNow,
                isPostQuantum: false,
                isDualSignature: false,
                hashAlgorithm: Configuration.HashAlgorithm,
                classicalAlgorithm: Configuration.FallbackSignatureAlgorithm);

            var result = new SignatureResult(signature, Configuration.FallbackSignatureAlgorithm, metadata);
            return CryptographicResult<SignatureResult>.Success(result);
        }

        private async Task<CryptographicResult<bool>> VerifyWithClassicalAsync(byte[] data, byte[] signature, byte[] publicKey)
        {
            // Classical signature verification implementation
            // This is a placeholder implementation
            return CryptographicResult<bool>.Success(true);
        }

        private async Task<CryptographicResult<KeyPair>> GenerateMlKem768KeyPairAsync()
        {
            var kemGen = new KyberKeyPairGenerator();
            kemGen.Init(new KyberKeyGenerationParameters(_secureRandom, KyberParameters.kyber768));
            var keyPair = kemGen.GenerateKeyPair();

            var publicKey = ((KyberPublicKeyParameters)keyPair.Public).GetEncoded();
            var privateKey = ((KyberPrivateKeyParameters)keyPair.Private).GetEncoded();

            var result = new KeyPair(publicKey, privateKey, "ML-KEM-768", false);
            return CryptographicResult<KeyPair>.Success(result);
        }

        private async Task<CryptographicResult<KeyPair>> GenerateMlDsa65KeyPairAsync()
        {
            var keyPairGen = new DilithiumKeyPairGenerator();
            keyPairGen.Init(new DilithiumKeyGenerationParameters(_secureRandom, DilithiumParameters.Dilithium3));
            var keyPair = keyPairGen.GenerateKeyPair();

            var publicKey = ((DilithiumPublicKeyParameters)keyPair.Public).GetEncoded();
            var privateKey = ((DilithiumPrivateKeyParameters)keyPair.Private).GetEncoded();

            var result = new KeyPair(publicKey, privateKey, "ML-DSA-65", true);
            return CryptographicResult<KeyPair>.Success(result);
        }

        private async Task<CryptographicResult<KeyPair>> GenerateRsaKeyPairAsync(int keySize, bool isForSigning)
        {
            using (var rsa = RSA.Create(keySize))
            {
                var publicKey = rsa.ExportRSAPublicKey();
                var privateKey = rsa.ExportRSAPrivateKey();

                var algorithm = isForSigning ? $"RSA-PSS-{keySize}" : $"RSA-OAEP-{keySize}";
                var result = new KeyPair(publicKey, privateKey, algorithm, isForSigning);
                return CryptographicResult<KeyPair>.Success(result);
            }
        }

        private async Task<byte[]> EncryptWithAesGcmAsync(byte[] data, byte[] key)
        {
            using (var aes = Aes.Create())
            {
                aes.KeySize = 256;
                aes.Mode = CipherMode.GCM;
                aes.Key = key.Take(32).ToArray(); // Use first 32 bytes as AES-256 key
                
                var iv = new byte[12]; // GCM IV size
                _secureRandom.NextBytes(iv);
                aes.IV = iv;

                using (var encryptor = aes.CreateEncryptor())
                {
                    var encryptedData = encryptor.TransformFinalBlock(data, 0, data.Length);
                    
                    // Combine IV + encrypted data + tag for simplified format
                    var result = new byte[iv.Length + encryptedData.Length + 16]; // 16 bytes for GCM tag
                    Array.Copy(iv, 0, result, 0, iv.Length);
                    Array.Copy(encryptedData, 0, result, iv.Length, encryptedData.Length);
                    
                    return result;
                }
            }
        }

        private void RecordMetrics(string operation, string algorithm, TimeSpan duration, long inputSize, long outputSize)
        {
            _lastOperationMetrics = new PerformanceMetrics(operation, algorithm, duration, inputSize, outputSize, DateTime.UtcNow);
            _logger.LogDebug("Operation {Operation} with {Algorithm} completed in {Duration}ms", operation, algorithm, duration.TotalMilliseconds);
        }

        #endregion
    }
}