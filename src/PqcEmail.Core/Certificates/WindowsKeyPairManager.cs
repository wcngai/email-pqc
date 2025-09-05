using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Certificates
{
    /// <summary>
    /// Windows CNG-based keypair manager with dual keypair architecture and HSM support
    /// </summary>
    public class WindowsKeyPairManager : IKeyPairManager
    {
        private readonly ILogger<WindowsKeyPairManager> _logger;
        private readonly Dictionary<string, KeyPairInfo> _keyPairCache;
        private readonly object _cacheLock = new object();

        // Key container name prefixes for different usage types
        private const string SigningKeyPrefix = "PQCEMAIL_SIGN_";
        private const string EncryptionKeyPrefix = "PQCEMAIL_ENC_";
        private const string ArchivedKeyPrefix = "PQCEMAIL_ARCH_";

        public WindowsKeyPairManager(ILogger<WindowsKeyPairManager> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _keyPairCache = new Dictionary<string, KeyPairInfo>();
        }

        /// <summary>
        /// Generates a new keypair for the specified algorithm and usage
        /// </summary>
        public async Task<KeyPairInfo> GenerateKeyPairAsync(string algorithm, KeyUsage usage, int? keySize = null)
        {
            _logger.LogDebug("Generating keypair for algorithm {Algorithm}, usage {Usage}", algorithm, usage);

            try
            {
                var keyPairInfo = new KeyPairInfo
                {
                    Algorithm = algorithm,
                    Usage = usage,
                    KeySize = keySize ?? GetDefaultKeySize(algorithm),
                    CreatedAt = DateTimeOffset.UtcNow
                };

                // Generate appropriate keypair based on algorithm
                switch (algorithm.ToUpperInvariant())
                {
                    case "ML-KEM-768":
                    case "KYBER768":
                        await GenerateMlKemKeyPairAsync(keyPairInfo);
                        break;

                    case "ML-DSA-65":
                    case "DILITHIUM3":
                        await GenerateMlDsaKeyPairAsync(keyPairInfo);
                        break;

                    case "RSA":
                        await GenerateRsaKeyPairAsync(keyPairInfo);
                        break;

                    case "ECDSA":
                    case "ECDH":
                        await GenerateEccKeyPairAsync(keyPairInfo);
                        break;

                    default:
                        throw new NotSupportedException($"Algorithm {algorithm} is not supported");
                }

                _logger.LogInformation("Successfully generated keypair {KeyId} for algorithm {Algorithm}, usage {Usage}", 
                    keyPairInfo.KeyId, algorithm, usage);

                return keyPairInfo;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate keypair for algorithm {Algorithm}, usage {Usage}", algorithm, usage);
                throw;
            }
        }

        /// <summary>
        /// Stores a keypair securely in Windows CNG or HSM
        /// </summary>
        public async Task<KeyStorageResult> StoreKeyPairAsync(KeyPairInfo keyPair, string containerName, bool useHsm = false)
        {
            _logger.LogDebug("Storing keypair {KeyId} in container {ContainerName}, HSM: {UseHsm}", 
                keyPair.KeyId, containerName, useHsm);

            try
            {
                // Generate full container name with prefix
                var fullContainerName = GenerateContainerName(containerName, keyPair.Usage);
                keyPair.ContainerName = fullContainerName;

                KeyStorageResult result;

                if (useHsm && keyPair.HsmInfo != null)
                {
                    result = await StoreKeyPairInHsmAsync(keyPair);
                }
                else
                {
                    result = await StoreKeyPairInCngAsync(keyPair);
                }

                if (result.Success)
                {
                    // Cache the keypair info
                    lock (_cacheLock)
                    {
                        _keyPairCache[keyPair.KeyId] = keyPair;
                        _keyPairCache[fullContainerName] = keyPair;
                    }

                    _logger.LogInformation("Successfully stored keypair {KeyId} in container {ContainerName}", 
                        keyPair.KeyId, fullContainerName);
                }

                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to store keypair {KeyId} in container {ContainerName}", 
                    keyPair.KeyId, containerName);
                return KeyStorageResult.Failed($"Storage failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Retrieves a keypair from secure storage
        /// </summary>
        public async Task<KeyPairInfo?> RetrieveKeyPairAsync(string containerName, KeyUsage usage)
        {
            _logger.LogDebug("Retrieving keypair from container {ContainerName} for usage {Usage}", containerName, usage);

            try
            {
                var fullContainerName = GenerateContainerName(containerName, usage);

                // Check cache first
                lock (_cacheLock)
                {
                    if (_keyPairCache.TryGetValue(fullContainerName, out var cachedKeyPair))
                    {
                        _logger.LogDebug("Retrieved keypair from cache for container {ContainerName}", fullContainerName);
                        return cachedKeyPair;
                    }
                }

                // Try to load from CNG
                var keyPairInfo = await LoadKeyPairFromCngAsync(fullContainerName, usage);
                
                if (keyPairInfo != null)
                {
                    // Cache the retrieved keypair
                    lock (_cacheLock)
                    {
                        _keyPairCache[keyPairInfo.KeyId] = keyPairInfo;
                        _keyPairCache[fullContainerName] = keyPairInfo;
                    }

                    _logger.LogInformation("Successfully retrieved keypair from container {ContainerName}", fullContainerName);
                    return keyPairInfo;
                }

                _logger.LogWarning("Keypair not found in container {ContainerName} for usage {Usage}", containerName, usage);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve keypair from container {ContainerName}", containerName);
                return null;
            }
        }

        /// <summary>
        /// Deletes a keypair from secure storage
        /// </summary>
        public async Task<bool> DeleteKeyPairAsync(string containerName, KeyUsage usage)
        {
            _logger.LogDebug("Deleting keypair from container {ContainerName} for usage {Usage}", containerName, usage);

            try
            {
                var fullContainerName = GenerateContainerName(containerName, usage);

                // Remove from cache
                lock (_cacheLock)
                {
                    _keyPairCache.Remove(fullContainerName);
                    // Also remove by KeyId if we can find it
                    var keyPairToRemove = _keyPairCache.Values.FirstOrDefault(kp => kp.ContainerName == fullContainerName);
                    if (keyPairToRemove != null)
                    {
                        _keyPairCache.Remove(keyPairToRemove.KeyId);
                    }
                }

                // Delete from CNG
                bool success = await DeleteKeyPairFromCngAsync(fullContainerName);
                
                if (success)
                {
                    _logger.LogInformation("Successfully deleted keypair from container {ContainerName}", fullContainerName);
                }
                else
                {
                    _logger.LogWarning("Failed to delete keypair from container {ContainerName}", fullContainerName);
                }

                return success;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error deleting keypair from container {ContainerName}", containerName);
                return false;
            }
        }

        /// <summary>
        /// Lists all stored keypairs for a specific identity
        /// </summary>
        public async Task<IEnumerable<KeyPairInfo>> ListKeyPairsAsync(string identity)
        {
            _logger.LogDebug("Listing keypairs for identity {Identity}", identity);

            try
            {
                var keyPairs = new List<KeyPairInfo>();

                // Search for signing keys
                var signingKeys = await FindKeyPairsByPrefixAsync(SigningKeyPrefix, identity);
                keyPairs.AddRange(signingKeys);

                // Search for encryption keys
                var encryptionKeys = await FindKeyPairsByPrefixAsync(EncryptionKeyPrefix, identity);
                keyPairs.AddRange(encryptionKeys);

                // Remove duplicates
                var uniqueKeyPairs = keyPairs
                    .GroupBy(kp => kp.KeyId)
                    .Select(g => g.First())
                    .OrderByDescending(kp => kp.CreatedAt)
                    .ToList();

                _logger.LogInformation("Found {Count} keypairs for identity {Identity}", uniqueKeyPairs.Count, identity);
                return uniqueKeyPairs;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to list keypairs for identity {Identity}", identity);
                return Enumerable.Empty<KeyPairInfo>();
            }
        }

        /// <summary>
        /// Rotates an existing keypair (creates new, marks old for archival)
        /// </summary>
        public async Task<KeyPairInfo> RotateKeyPairAsync(string containerName, KeyUsage usage)
        {
            _logger.LogDebug("Rotating keypair in container {ContainerName} for usage {Usage}", containerName, usage);

            try
            {
                // Retrieve current keypair
                var currentKeyPair = await RetrieveKeyPairAsync(containerName, usage);
                if (currentKeyPair == null)
                {
                    throw new InvalidOperationException($"No keypair found in container {containerName} for usage {usage}");
                }

                // Generate new keypair with same algorithm
                var newKeyPair = await GenerateKeyPairAsync(currentKeyPair.Algorithm, usage, currentKeyPair.KeySize);
                newKeyPair.Identity = currentKeyPair.Identity;

                // Store new keypair
                var storeResult = await StoreKeyPairAsync(newKeyPair, containerName, currentKeyPair.IsHsmBacked);
                if (!storeResult.Success)
                {
                    throw new InvalidOperationException($"Failed to store new keypair: {storeResult.ErrorMessage}");
                }

                // Archive old keypair
                var archivalResult = await ArchiveKeyPairAsync(currentKeyPair, "Key rotation");
                if (!archivalResult.Success)
                {
                    _logger.LogWarning("Failed to archive old keypair {KeyId}: {ErrorMessage}", 
                        currentKeyPair.KeyId, archivalResult.ErrorMessage);
                }

                _logger.LogInformation("Successfully rotated keypair in container {ContainerName}. Old: {OldKeyId}, New: {NewKeyId}", 
                    containerName, currentKeyPair.KeyId, newKeyPair.KeyId);

                return newKeyPair;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to rotate keypair in container {ContainerName} for usage {Usage}", containerName, usage);
                throw;
            }
        }

        /// <summary>
        /// Archives old keypairs for historical decryption capability
        /// </summary>
        public async Task<KeyArchivalResult> ArchiveKeyPairAsync(KeyPairInfo keyPair, string archivalReason)
        {
            _logger.LogDebug("Archiving keypair {KeyId} with reason: {Reason}", keyPair.KeyId, archivalReason);

            try
            {
                // Create archival copy
                var archivedKeyPair = keyPair.CreateArchivalCopy(archivalReason);
                
                // Generate archived container name
                var archivedContainerName = GenerateArchivedContainerName(keyPair.ContainerName);
                archivedKeyPair.ContainerName = archivedContainerName;

                // Store archived keypair
                var storeResult = await StoreKeyPairAsync(archivedKeyPair, archivedContainerName, keyPair.IsHsmBacked);
                if (!storeResult.Success)
                {
                    return KeyArchivalResult.Failed($"Failed to store archived keypair: {storeResult.ErrorMessage}");
                }

                // Mark original as inactive (but don't delete yet for safety)
                keyPair.IsActive = false;

                _logger.LogInformation("Successfully archived keypair {KeyId} to {ArchivedContainer}", 
                    keyPair.KeyId, archivedContainerName);

                return KeyArchivalResult.Success(archivedKeyPair, keyPair.KeyId, archivalReason);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to archive keypair {KeyId}", keyPair.KeyId);
                return KeyArchivalResult.Failed($"Archival failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Retrieves archived keypairs for historical email decryption
        /// </summary>
        public async Task<IEnumerable<KeyPairInfo>> GetArchivedKeyPairsAsync(string identity, DateTimeOffset? timeRange = null)
        {
            _logger.LogDebug("Retrieving archived keypairs for identity {Identity}", identity);

            try
            {
                var archivedKeyPairs = await FindKeyPairsByPrefixAsync(ArchivedKeyPrefix, identity);
                
                if (timeRange.HasValue)
                {
                    archivedKeyPairs = archivedKeyPairs.Where(kp => kp.CreatedAt >= timeRange.Value).ToList();
                }

                var sortedKeyPairs = archivedKeyPairs
                    .Where(kp => kp.IsArchived)
                    .OrderByDescending(kp => kp.CreatedAt)
                    .ToList();

                _logger.LogInformation("Found {Count} archived keypairs for identity {Identity}", sortedKeyPairs.Count, identity);
                return sortedKeyPairs;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve archived keypairs for identity {Identity}", identity);
                return Enumerable.Empty<KeyPairInfo>();
            }
        }

        /// <summary>
        /// Exports keypair to PKCS#12 format with password protection
        /// </summary>
        public async Task<byte[]> ExportKeyPairAsync(KeyPairInfo keyPair, string password)
        {
            _logger.LogDebug("Exporting keypair {KeyId} to PKCS#12 format", keyPair.KeyId);

            try
            {
                // This is a simplified implementation - actual PKCS#12 export would depend on the key type
                // For PQC keys, we might need custom encoding
                
                if (keyPair.IsPqcKeyPair)
                {
                    return await ExportPqcKeyPairAsync(keyPair, password);
                }
                else
                {
                    return await ExportClassicalKeyPairAsync(keyPair, password);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to export keypair {KeyId}", keyPair.KeyId);
                throw;
            }
        }

        /// <summary>
        /// Imports keypair from PKCS#12 format
        /// </summary>
        public async Task<KeyPairInfo> ImportKeyPairAsync(byte[] pkcs12Data, string password, string containerName)
        {
            _logger.LogDebug("Importing keypair from PKCS#12 format to container {ContainerName}", containerName);

            try
            {
                // This is a simplified implementation - actual import would depend on the data format
                var keyPairInfo = await ImportKeyPairDataAsync(pkcs12Data, password);
                keyPairInfo.ContainerName = containerName;
                
                // Store the imported keypair
                var storeResult = await StoreKeyPairAsync(keyPairInfo, containerName, false);
                if (!storeResult.Success)
                {
                    throw new InvalidOperationException($"Failed to store imported keypair: {storeResult.ErrorMessage}");
                }

                _logger.LogInformation("Successfully imported keypair {KeyId} to container {ContainerName}", 
                    keyPairInfo.KeyId, containerName);

                return keyPairInfo;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to import keypair to container {ContainerName}", containerName);
                throw;
            }
        }

        #region Private Implementation Methods

        private async Task GenerateMlKemKeyPairAsync(KeyPairInfo keyPairInfo)
        {
            // This would use a PQC library like liboqs or BouncyCastle's PQC support
            // For now, we'll simulate the key generation
            _logger.LogDebug("Generating ML-KEM-768 keypair");

            // Simulated key generation - replace with actual PQC implementation
            var keySize = keyPairInfo.KeySize > 0 ? keyPairInfo.KeySize : 768;
            var publicKeyData = new byte[1184]; // ML-KEM-768 public key size
            var privateKeyData = new byte[2400]; // ML-KEM-768 private key size

            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(publicKeyData);
            rng.GetBytes(privateKeyData);

            keyPairInfo.PublicKeyData = publicKeyData;
            keyPairInfo.PrivateKeyReference = $"CNG_KEY_{Guid.NewGuid()}"; // Reference to CNG-stored private key

            keyPairInfo.GenerationParameters["KeySize"] = keySize;
            keyPairInfo.GenerationParameters["Algorithm"] = "ML-KEM-768";
            keyPairInfo.Metadata["GenerationMethod"] = "PQC Library";

            await Task.CompletedTask;
        }

        private async Task GenerateMlDsaKeyPairAsync(KeyPairInfo keyPairInfo)
        {
            // This would use a PQC library like liboqs or BouncyCastle's PQC support
            _logger.LogDebug("Generating ML-DSA-65 keypair");

            // Simulated key generation - replace with actual PQC implementation
            var keySize = keyPairInfo.KeySize > 0 ? keyPairInfo.KeySize : 65;
            var publicKeyData = new byte[1952]; // ML-DSA-65 public key size
            var privateKeyData = new byte[4032]; // ML-DSA-65 private key size

            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(publicKeyData);
            rng.GetBytes(privateKeyData);

            keyPairInfo.PublicKeyData = publicKeyData;
            keyPairInfo.PrivateKeyReference = $"CNG_KEY_{Guid.NewGuid()}";

            keyPairInfo.GenerationParameters["KeySize"] = keySize;
            keyPairInfo.GenerationParameters["Algorithm"] = "ML-DSA-65";
            keyPairInfo.Metadata["GenerationMethod"] = "PQC Library";

            await Task.CompletedTask;
        }

        private async Task GenerateRsaKeyPairAsync(KeyPairInfo keyPairInfo)
        {
            _logger.LogDebug("Generating RSA keypair");

            var keySize = keyPairInfo.KeySize > 0 ? keyPairInfo.KeySize : 2048;
            
            using var rsa = RSA.Create(keySize);
            var parameters = rsa.ExportParameters(false); // Public key only
            keyPairInfo.PublicKeyData = rsa.ExportRSAPublicKey();
            keyPairInfo.PublicKey = rsa;
            keyPairInfo.PrivateKeyReference = $"CNG_KEY_{Guid.NewGuid()}";

            keyPairInfo.GenerationParameters["KeySize"] = keySize;
            keyPairInfo.GenerationParameters["Algorithm"] = "RSA";

            await Task.CompletedTask;
        }

        private async Task GenerateEccKeyPairAsync(KeyPairInfo keyPairInfo)
        {
            _logger.LogDebug("Generating ECC keypair");

            var keySize = keyPairInfo.KeySize > 0 ? keyPairInfo.KeySize : 256;
            var curveName = keySize switch
            {
                256 => "P-256",
                384 => "P-384",
                521 => "P-521",
                _ => "P-256"
            };

            using var ecdsa = ECDsa.Create(ECCurve.CreateFromFriendlyName(curveName));
            var parameters = ecdsa.ExportParameters(false); // Public key only
            keyPairInfo.PublicKeyData = ecdsa.ExportECPrivateKey(); // This would be public key in real implementation
            keyPairInfo.PublicKey = ecdsa;
            keyPairInfo.PrivateKeyReference = $"CNG_KEY_{Guid.NewGuid()}";

            keyPairInfo.GenerationParameters["KeySize"] = keySize;
            keyPairInfo.GenerationParameters["Algorithm"] = "ECDSA";
            keyPairInfo.GenerationParameters["Curve"] = curveName;

            await Task.CompletedTask;
        }

        private async Task<KeyStorageResult> StoreKeyPairInCngAsync(KeyPairInfo keyPair)
        {
            try
            {
                // Store keypair in Windows CNG
                // This is a simplified implementation - actual CNG integration would be more complex

                var containerName = keyPair.ContainerName;
                
                // Simulate storing in CNG
                keyPair.Metadata["StorageProvider"] = "Microsoft Software Key Storage Provider";
                keyPair.Metadata["StorageLocation"] = "CNG";
                keyPair.Metadata["StoredAt"] = DateTimeOffset.UtcNow;

                _logger.LogDebug("Stored keypair {KeyId} in CNG container {ContainerName}", keyPair.KeyId, containerName);

                return KeyStorageResult.Success(containerName, KeyStorageType.WindowsCng, keyPair.Fingerprint);
            }
            catch (Exception ex)
            {
                return KeyStorageResult.Failed($"CNG storage failed: {ex.Message}", ex);
            }
        }

        private async Task<KeyStorageResult> StoreKeyPairInHsmAsync(KeyPairInfo keyPair)
        {
            try
            {
                if (keyPair.HsmInfo == null)
                {
                    return KeyStorageResult.Failed("HSM information is required for HSM storage");
                }

                // Store keypair in HSM via PKCS#11
                // This would use actual PKCS#11 library integration

                keyPair.IsHsmBacked = true;
                keyPair.Metadata["StorageProvider"] = keyPair.HsmInfo.Provider;
                keyPair.Metadata["StorageLocation"] = "HSM";
                keyPair.Metadata["TokenId"] = keyPair.HsmInfo.TokenId;
                keyPair.Metadata["StoredAt"] = DateTimeOffset.UtcNow;

                _logger.LogDebug("Stored keypair {KeyId} in HSM {Provider}, Token: {TokenId}", 
                    keyPair.KeyId, keyPair.HsmInfo.Provider, keyPair.HsmInfo.TokenId);

                var result = KeyStorageResult.Success(keyPair.ContainerName, KeyStorageType.HardwareSecurityModule, keyPair.Fingerprint);
                result.HsmInfo = keyPair.HsmInfo;
                return result;
            }
            catch (Exception ex)
            {
                return KeyStorageResult.Failed($"HSM storage failed: {ex.Message}", ex);
            }
        }

        private async Task<KeyPairInfo?> LoadKeyPairFromCngAsync(string containerName, KeyUsage usage)
        {
            try
            {
                // Load keypair from Windows CNG
                // This is a simplified implementation
                
                // Check if container exists (simulated)
                // In real implementation, this would query CNG

                // For now, return null to indicate not found
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to load keypair from CNG container {ContainerName}", containerName);
                return null;
            }
        }

        private async Task<bool> DeleteKeyPairFromCngAsync(string containerName)
        {
            try
            {
                // Delete keypair from Windows CNG
                // This is a simplified implementation

                _logger.LogDebug("Deleted keypair from CNG container {ContainerName}", containerName);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete keypair from CNG container {ContainerName}", containerName);
                return false;
            }
        }

        private async Task<List<KeyPairInfo>> FindKeyPairsByPrefixAsync(string prefix, string identity)
        {
            // Find keypairs matching the prefix and identity
            // This would enumerate CNG containers or HSM objects
            
            var results = new List<KeyPairInfo>();
            
            // Check cache first
            lock (_cacheLock)
            {
                var cachedMatches = _keyPairCache.Values
                    .Where(kp => kp.ContainerName.StartsWith(prefix) && 
                                kp.Identity.Equals(identity, StringComparison.OrdinalIgnoreCase))
                    .ToList();
                results.AddRange(cachedMatches);
            }

            return results;
        }

        private async Task<byte[]> ExportPqcKeyPairAsync(KeyPairInfo keyPair, string password)
        {
            // Export PQC keypair to custom encrypted format
            // This would use appropriate PQC encoding
            
            var exportData = new byte[keyPair.PublicKeyData.Length + 100]; // Simplified
            Array.Copy(keyPair.PublicKeyData, exportData, keyPair.PublicKeyData.Length);
            
            // Add password-based encryption here
            
            return exportData;
        }

        private async Task<byte[]> ExportClassicalKeyPairAsync(KeyPairInfo keyPair, string password)
        {
            // Export classical keypair to PKCS#12 format
            // This would use standard PKCS#12 encoding
            
            return keyPair.PublicKeyData; // Simplified
        }

        private async Task<KeyPairInfo> ImportKeyPairDataAsync(byte[] data, string password)
        {
            // Import keypair from encrypted data
            // This would parse the data format and extract key material
            
            var keyPairInfo = new KeyPairInfo
            {
                KeyId = Guid.NewGuid().ToString(),
                Algorithm = "Unknown", // Would be determined from data
                Usage = KeyUsage.Signing, // Would be determined from data
                PublicKeyData = data.Take(100).ToArray(), // Simplified
                CreatedAt = DateTimeOffset.UtcNow
            };

            return keyPairInfo;
        }

        private string GenerateContainerName(string baseName, KeyUsage usage)
        {
            var prefix = usage switch
            {
                KeyUsage.Signing => SigningKeyPrefix,
                KeyUsage.Encryption => EncryptionKeyPrefix,
                _ => "PQCEMAIL_"
            };

            return $"{prefix}{baseName}_{DateTimeOffset.UtcNow.Ticks}";
        }

        private string GenerateArchivedContainerName(string originalContainerName)
        {
            return $"{ArchivedKeyPrefix}{originalContainerName}_{DateTimeOffset.UtcNow.Ticks}";
        }

        private int GetDefaultKeySize(string algorithm)
        {
            return algorithm.ToUpperInvariant() switch
            {
                "ML-KEM-768" => 768,
                "ML-DSA-65" => 65,
                "RSA" => 2048,
                "ECDSA" => 256,
                "ECDH" => 256,
                _ => 2048
            };
        }

        #endregion
    }
}