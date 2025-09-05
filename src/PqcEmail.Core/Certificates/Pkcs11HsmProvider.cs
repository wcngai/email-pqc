using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Certificates
{
    /// <summary>
    /// PKCS#11 HSM provider implementation for hardware security module operations
    /// </summary>
    public class Pkcs11HsmProvider : IHsmProvider
    {
        private readonly ILogger<Pkcs11HsmProvider> _logger;
        private string? _libraryPath;
        private string? _tokenLabel;
        private bool _isInitialized;
        private bool _isAuthenticated;
        private HsmTokenInfo? _currentToken;

        // Simulated PKCS#11 session state
        private readonly Dictionary<string, HsmKeyPairInfo> _hsmKeys;
        private readonly object _sessionLock = new object();

        public Pkcs11HsmProvider(ILogger<Pkcs11HsmProvider> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _hsmKeys = new Dictionary<string, HsmKeyPairInfo>();
        }

        public bool IsConnected => _isInitialized && _isAuthenticated;

        public HsmTokenInfo? CurrentToken => _currentToken;

        /// <summary>
        /// Initializes the HSM connection with PKCS#11 library
        /// </summary>
        public async Task<bool> InitializeAsync(string libraryPath, string tokenLabel)
        {
            _logger.LogDebug("Initializing HSM connection with library: {LibraryPath}, token: {TokenLabel}", 
                libraryPath, tokenLabel);

            try
            {
                _libraryPath = libraryPath;
                _tokenLabel = tokenLabel;

                // In a real implementation, this would:
                // 1. Load PKCS#11 library using P/Invoke or wrapper library
                // 2. Call C_Initialize
                // 3. Get slot list and find token
                // 4. Open session

                // Simulate successful initialization
                _isInitialized = true;
                
                // Create mock token info
                _currentToken = new HsmTokenInfo
                {
                    Label = tokenLabel,
                    SerialNumber = "HSM001234567",
                    ManufacturerID = "MockHSM",
                    Model = "Virtual HSM v1.0",
                    FirmwareVersion = "1.0.0",
                    IsWriteProtected = false,
                    RequiresLogin = true,
                    IsInitialized = true,
                    TotalPublicMemory = 1024 * 1024,
                    FreePublicMemory = 512 * 1024,
                    TotalPrivateMemory = 1024 * 1024,
                    FreePrivateMemory = 800 * 1024,
                    SupportedMechanisms = new List<string> 
                    { 
                        "CKM_RSA_PKCS", 
                        "CKM_ECDSA", 
                        "CKM_AES_GCM",
                        "CKM_ML_KEM_768",  // PQC mechanisms
                        "CKM_ML_DSA_65"
                    }
                };

                _logger.LogInformation("HSM initialized successfully. Token: {TokenLabel}", tokenLabel);
                return true;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to initialize HSM connection");
                return false;
            }
        }

        /// <summary>
        /// Authenticates with the HSM token
        /// </summary>
        public async Task<HsmAuthenticationResult> AuthenticateAsync(string pin, HsmAuthMethod authMethod = HsmAuthMethod.Pin)
        {
            _logger.LogDebug("Authenticating with HSM using method: {AuthMethod}", authMethod);

            try
            {
                if (!_isInitialized)
                {
                    return HsmAuthenticationResult.Failed("HSM not initialized");
                }

                // In a real implementation, this would call C_Login
                
                // Simulate authentication validation
                if (string.IsNullOrEmpty(pin) || pin.Length < 4)
                {
                    return HsmAuthenticationResult.Failed("Invalid PIN format");
                }

                _isAuthenticated = true;

                _logger.LogInformation("HSM authentication successful");
                return HsmAuthenticationResult.Success(authMethod, TimeSpan.FromHours(8));
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HSM authentication failed");
                return HsmAuthenticationResult.Failed($"Authentication error: {ex.Message}");
            }
        }

        /// <summary>
        /// Lists all available HSM tokens
        /// </summary>
        public async Task<IEnumerable<HsmTokenInfo>> ListTokensAsync()
        {
            _logger.LogDebug("Listing available HSM tokens");

            try
            {
                // In a real implementation, this would:
                // 1. Call C_GetSlotList
                // 2. For each slot, call C_GetTokenInfo

                var tokens = new List<HsmTokenInfo>();
                
                if (_currentToken != null)
                {
                    tokens.Add(_currentToken);
                }

                // Add some mock additional tokens
                tokens.Add(new HsmTokenInfo
                {
                    Label = "BackupToken",
                    SerialNumber = "HSM001234568",
                    ManufacturerID = "MockHSM",
                    Model = "Virtual HSM v1.0",
                    IsInitialized = true,
                    RequiresLogin = true
                });

                _logger.LogInformation("Found {Count} HSM tokens", tokens.Count);
                return tokens;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to list HSM tokens");
                return Enumerable.Empty<HsmTokenInfo>();
            }
        }

        /// <summary>
        /// Generates a keypair directly in the HSM
        /// </summary>
        public async Task<HsmKeyPairInfo> GenerateKeyPairAsync(string algorithm, int keySize, string keyLabel, KeyUsage usage)
        {
            _logger.LogDebug("Generating HSM keypair: Algorithm={Algorithm}, KeySize={KeySize}, Label={Label}, Usage={Usage}",
                algorithm, keySize, keyLabel, usage);

            try
            {
                if (!IsConnected)
                {
                    throw new InvalidOperationException("HSM not connected or authenticated");
                }

                // In a real implementation, this would:
                // 1. Set up key generation template
                // 2. Call C_GenerateKeyPair

                var keyPairInfo = new HsmKeyPairInfo
                {
                    KeyLabel = keyLabel,
                    KeyId = Guid.NewGuid().ToString(),
                    Algorithm = algorithm,
                    KeySize = keySize,
                    Usage = usage,
                    IsPrivate = true,
                    IsExtractable = false, // HSM keys typically non-extractable
                    IsModifiable = false,
                    Token = _currentToken
                };

                // Generate mock public key data based on algorithm
                keyPairInfo.PublicKeyData = algorithm.ToUpperInvariant() switch
                {
                    "ML-KEM-768" => new byte[1184], // ML-KEM-768 public key size
                    "ML-DSA-65" => new byte[1952],  // ML-DSA-65 public key size
                    "RSA" => new byte[keySize / 8],
                    "ECDSA" => new byte[keySize / 8],
                    _ => new byte[256]
                };

                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(keyPairInfo.PublicKeyData);

                // Set algorithm-specific attributes
                keyPairInfo.Attributes["CKA_ENCRYPT"] = usage == KeyUsage.Encryption;
                keyPairInfo.Attributes["CKA_DECRYPT"] = usage == KeyUsage.Encryption;
                keyPairInfo.Attributes["CKA_SIGN"] = usage == KeyUsage.Signing;
                keyPairInfo.Attributes["CKA_VERIFY"] = usage == KeyUsage.Signing;
                keyPairInfo.Attributes["CKA_TOKEN"] = true;
                keyPairInfo.Attributes["CKA_PRIVATE"] = true;

                // Store in HSM simulation
                lock (_sessionLock)
                {
                    _hsmKeys[keyLabel] = keyPairInfo;
                }

                _logger.LogInformation("Successfully generated HSM keypair with label: {Label}", keyLabel);
                return keyPairInfo;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate HSM keypair with label: {Label}", keyLabel);
                throw;
            }
        }

        /// <summary>
        /// Stores an existing keypair in the HSM
        /// </summary>
        public async Task<HsmStorageResult> StoreKeyPairAsync(KeyPairInfo keyPair, string keyLabel)
        {
            _logger.LogDebug("Storing keypair in HSM with label: {Label}", keyLabel);

            try
            {
                if (!IsConnected)
                {
                    return HsmStorageResult.Failed("HSM not connected or authenticated");
                }

                // Convert KeyPairInfo to HsmKeyPairInfo
                var hsmKeyPair = new HsmKeyPairInfo
                {
                    KeyLabel = keyLabel,
                    KeyId = keyPair.KeyId,
                    Algorithm = keyPair.Algorithm,
                    KeySize = keyPair.KeySize,
                    Usage = keyPair.Usage,
                    PublicKeyData = keyPair.PublicKeyData,
                    IsPrivate = true,
                    IsExtractable = false,
                    Token = _currentToken
                };

                // Store in HSM simulation
                lock (_sessionLock)
                {
                    _hsmKeys[keyLabel] = hsmKeyPair;
                }

                _logger.LogInformation("Successfully stored keypair in HSM with label: {Label}", keyLabel);
                return HsmStorageResult.Success(keyLabel, keyPair.KeyId);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to store keypair in HSM with label: {Label}", keyLabel);
                return HsmStorageResult.Failed($"Storage failed: {ex.Message}", ex);
            }
        }

        /// <summary>
        /// Retrieves a keypair from the HSM
        /// </summary>
        public async Task<HsmKeyPairInfo?> RetrieveKeyPairAsync(string keyLabel)
        {
            _logger.LogDebug("Retrieving keypair from HSM with label: {Label}", keyLabel);

            try
            {
                if (!IsConnected)
                {
                    return null;
                }

                lock (_sessionLock)
                {
                    if (_hsmKeys.TryGetValue(keyLabel, out var keyPairInfo))
                    {
                        _logger.LogInformation("Successfully retrieved keypair from HSM with label: {Label}", keyLabel);
                        return keyPairInfo;
                    }
                }

                _logger.LogWarning("Keypair not found in HSM with label: {Label}", keyLabel);
                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve keypair from HSM with label: {Label}", keyLabel);
                return null;
            }
        }

        /// <summary>
        /// Deletes a keypair from the HSM
        /// </summary>
        public async Task<bool> DeleteKeyPairAsync(string keyLabel)
        {
            _logger.LogDebug("Deleting keypair from HSM with label: {Label}", keyLabel);

            try
            {
                if (!IsConnected)
                {
                    return false;
                }

                lock (_sessionLock)
                {
                    bool removed = _hsmKeys.Remove(keyLabel);
                    if (removed)
                    {
                        _logger.LogInformation("Successfully deleted keypair from HSM with label: {Label}", keyLabel);
                    }
                    else
                    {
                        _logger.LogWarning("Keypair not found for deletion in HSM with label: {Label}", keyLabel);
                    }
                    return removed;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to delete keypair from HSM with label: {Label}", keyLabel);
                return false;
            }
        }

        /// <summary>
        /// Lists all keypairs stored in the HSM
        /// </summary>
        public async Task<IEnumerable<HsmKeyPairInfo>> ListKeyPairsAsync()
        {
            _logger.LogDebug("Listing all keypairs in HSM");

            try
            {
                if (!IsConnected)
                {
                    return Enumerable.Empty<HsmKeyPairInfo>();
                }

                lock (_sessionLock)
                {
                    var keyPairs = _hsmKeys.Values.ToList();
                    _logger.LogInformation("Found {Count} keypairs in HSM", keyPairs.Count);
                    return keyPairs;
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to list keypairs in HSM");
                return Enumerable.Empty<HsmKeyPairInfo>();
            }
        }

        /// <summary>
        /// Performs cryptographic signing operation using HSM-stored key
        /// </summary>
        public async Task<byte[]> SignAsync(string keyLabel, byte[] data, HashAlgorithmName hashAlgorithm)
        {
            _logger.LogDebug("Performing HSM signing operation with key: {Label}", keyLabel);

            try
            {
                if (!IsConnected)
                {
                    throw new InvalidOperationException("HSM not connected or authenticated");
                }

                var keyPair = await RetrieveKeyPairAsync(keyLabel);
                if (keyPair == null)
                {
                    throw new InvalidOperationException($"Signing key not found: {keyLabel}");
                }

                if (keyPair.Usage != KeyUsage.Signing)
                {
                    throw new InvalidOperationException($"Key {keyLabel} is not configured for signing");
                }

                // In a real implementation, this would:
                // 1. Set up signing template with mechanism
                // 2. Call C_SignInit, C_Sign (or C_SignUpdate/C_SignFinal for multi-part)

                // Simulate signing operation
                byte[] signature;
                
                if (keyPair.Algorithm.StartsWith("ML-DSA"))
                {
                    // PQC signature - larger signature size
                    signature = new byte[3293]; // ML-DSA-65 signature size
                }
                else if (keyPair.Algorithm == "RSA")
                {
                    signature = new byte[keyPair.KeySize / 8]; // RSA signature size
                }
                else if (keyPair.Algorithm == "ECDSA")
                {
                    signature = new byte[keyPair.KeySize / 4]; // ECDSA signature size (approximate)
                }
                else
                {
                    signature = new byte[256]; // Default signature size
                }

                // Generate mock signature
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(signature);

                _logger.LogInformation("Successfully performed HSM signing operation with key: {Label}, signature size: {Size}",
                    keyLabel, signature.Length);

                return signature;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HSM signing operation failed with key: {Label}", keyLabel);
                throw;
            }
        }

        /// <summary>
        /// Verifies a digital signature using HSM-stored public key
        /// </summary>
        public async Task<bool> VerifySignatureAsync(string keyLabel, byte[] data, byte[] signature, HashAlgorithmName hashAlgorithm)
        {
            _logger.LogDebug("Performing HSM signature verification with key: {Label}", keyLabel);

            try
            {
                if (!IsConnected)
                {
                    throw new InvalidOperationException("HSM not connected or authenticated");
                }

                var keyPair = await RetrieveKeyPairAsync(keyLabel);
                if (keyPair == null)
                {
                    throw new InvalidOperationException($"Verification key not found: {keyLabel}");
                }

                // In a real implementation, this would:
                // 1. Set up verification template
                // 2. Call C_VerifyInit, C_Verify

                // Simulate verification (always returns true for demo)
                bool isValid = true; // In real implementation, this would be actual verification result

                _logger.LogInformation("HSM signature verification completed with key: {Label}, result: {Result}",
                    keyLabel, isValid);

                return isValid;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HSM signature verification failed with key: {Label}", keyLabel);
                return false;
            }
        }

        /// <summary>
        /// Performs key encapsulation (for PQC KEM algorithms)
        /// </summary>
        public async Task<HsmEncapsulationResult> EncapsulateAsync(string keyLabel, int sharedSecretLength)
        {
            _logger.LogDebug("Performing HSM key encapsulation with key: {Label}", keyLabel);

            try
            {
                if (!IsConnected)
                {
                    throw new InvalidOperationException("HSM not connected or authenticated");
                }

                var keyPair = await RetrieveKeyPairAsync(keyLabel);
                if (keyPair == null)
                {
                    throw new InvalidOperationException($"Encapsulation key not found: {keyLabel}");
                }

                if (!keyPair.Algorithm.StartsWith("ML-KEM"))
                {
                    throw new InvalidOperationException($"Key {keyLabel} does not support KEM operations");
                }

                // Simulate ML-KEM encapsulation
                var result = new HsmEncapsulationResult
                {
                    Algorithm = keyPair.Algorithm,
                    Ciphertext = new byte[1088], // ML-KEM-768 ciphertext size
                    SharedSecret = new byte[sharedSecretLength]
                };

                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(result.Ciphertext);
                rng.GetBytes(result.SharedSecret);

                result.Parameters["KeyLabel"] = keyLabel;
                result.Parameters["Algorithm"] = keyPair.Algorithm;

                _logger.LogInformation("Successfully performed HSM key encapsulation with key: {Label}", keyLabel);
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HSM key encapsulation failed with key: {Label}", keyLabel);
                throw;
            }
        }

        /// <summary>
        /// Performs key decapsulation (for PQC KEM algorithms)
        /// </summary>
        public async Task<byte[]> DecapsulateAsync(string keyLabel, byte[] ciphertext)
        {
            _logger.LogDebug("Performing HSM key decapsulation with key: {Label}", keyLabel);

            try
            {
                if (!IsConnected)
                {
                    throw new InvalidOperationException("HSM not connected or authenticated");
                }

                var keyPair = await RetrieveKeyPairAsync(keyLabel);
                if (keyPair == null)
                {
                    throw new InvalidOperationException($"Decapsulation key not found: {keyLabel}");
                }

                if (!keyPair.Algorithm.StartsWith("ML-KEM"))
                {
                    throw new InvalidOperationException($"Key {keyLabel} does not support KEM operations");
                }

                // Simulate ML-KEM decapsulation
                var sharedSecret = new byte[32]; // Standard shared secret size
                using var rng = RandomNumberGenerator.Create();
                rng.GetBytes(sharedSecret);

                _logger.LogInformation("Successfully performed HSM key decapsulation with key: {Label}", keyLabel);
                return sharedSecret;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HSM key decapsulation failed with key: {Label}", keyLabel);
                throw;
            }
        }

        /// <summary>
        /// Encrypts data using HSM-stored key
        /// </summary>
        public async Task<byte[]> EncryptAsync(string keyLabel, byte[] plaintext, string algorithm = "AES-GCM")
        {
            _logger.LogDebug("Performing HSM encryption with key: {Label}, algorithm: {Algorithm}", keyLabel, algorithm);

            try
            {
                if (!IsConnected)
                {
                    throw new InvalidOperationException("HSM not connected or authenticated");
                }

                // Simulate encryption - in real implementation would use HSM
                var encrypted = new byte[plaintext.Length + 16]; // Add space for authentication tag
                Array.Copy(plaintext, encrypted, plaintext.Length);
                
                using var rng = RandomNumberGenerator.Create();
                var authTag = new byte[16];
                rng.GetBytes(authTag);
                Array.Copy(authTag, 0, encrypted, plaintext.Length, 16);

                _logger.LogInformation("Successfully performed HSM encryption with key: {Label}", keyLabel);
                return encrypted;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HSM encryption failed with key: {Label}", keyLabel);
                throw;
            }
        }

        /// <summary>
        /// Decrypts data using HSM-stored key
        /// </summary>
        public async Task<byte[]> DecryptAsync(string keyLabel, byte[] ciphertext, string algorithm = "AES-GCM")
        {
            _logger.LogDebug("Performing HSM decryption with key: {Label}, algorithm: {Algorithm}", keyLabel, algorithm);

            try
            {
                if (!IsConnected)
                {
                    throw new InvalidOperationException("HSM not connected or authenticated");
                }

                // Simulate decryption - in real implementation would use HSM
                var decrypted = new byte[ciphertext.Length - 16]; // Remove authentication tag
                Array.Copy(ciphertext, decrypted, decrypted.Length);

                _logger.LogInformation("Successfully performed HSM decryption with key: {Label}", keyLabel);
                return decrypted;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "HSM decryption failed with key: {Label}", keyLabel);
                throw;
            }
        }

        /// <summary>
        /// Gets HSM token information
        /// </summary>
        public async Task<HsmTokenInfo?> GetTokenInfoAsync(string tokenLabel)
        {
            _logger.LogDebug("Getting HSM token info for: {TokenLabel}", tokenLabel);

            try
            {
                if (_currentToken?.Label == tokenLabel)
                {
                    return _currentToken;
                }

                return null;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get HSM token info for: {TokenLabel}", tokenLabel);
                return null;
            }
        }

        /// <summary>
        /// Gets HSM mechanism (algorithm) information
        /// </summary>
        public async Task<HsmMechanismInfo?> GetMechanismInfoAsync(string mechanismType)
        {
            _logger.LogDebug("Getting HSM mechanism info for: {MechanismType}", mechanismType);

            try
            {
                // Return mock mechanism information
                return mechanismType.ToUpperInvariant() switch
                {
                    "CKM_ML_KEM_768" => new HsmMechanismInfo
                    {
                        MechanismType = mechanismType,
                        Name = "ML-KEM-768",
                        MinKeySize = 768,
                        MaxKeySize = 768,
                        SupportsGenerate = true,
                        SupportsGenerateKeyPair = true,
                        SupportsEncryption = true,
                        SupportsDecryption = true
                    },
                    "CKM_ML_DSA_65" => new HsmMechanismInfo
                    {
                        MechanismType = mechanismType,
                        Name = "ML-DSA-65",
                        MinKeySize = 65,
                        MaxKeySize = 65,
                        SupportsGenerate = true,
                        SupportsGenerateKeyPair = true,
                        SupportsSignature = true,
                        SupportsVerify = true
                    },
                    "CKM_RSA_PKCS" => new HsmMechanismInfo
                    {
                        MechanismType = mechanismType,
                        Name = "RSA PKCS#1",
                        MinKeySize = 1024,
                        MaxKeySize = 4096,
                        SupportsGenerate = true,
                        SupportsGenerateKeyPair = true,
                        SupportsSignature = true,
                        SupportsVerify = true,
                        SupportsEncryption = true,
                        SupportsDecryption = true
                    },
                    _ => null
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to get HSM mechanism info for: {MechanismType}", mechanismType);
                return null;
            }
        }

        /// <summary>
        /// Tests HSM connectivity and functionality
        /// </summary>
        public async Task<HsmHealthCheckResult> PerformHealthCheckAsync()
        {
            _logger.LogDebug("Performing HSM health check");

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();
            var issues = new List<string>();

            try
            {
                // Check initialization
                if (!_isInitialized)
                {
                    issues.Add("HSM not initialized");
                }

                // Check authentication
                if (!_isAuthenticated)
                {
                    issues.Add("HSM not authenticated");
                }

                // Check token availability
                if (_currentToken == null)
                {
                    issues.Add("No current token available");
                }

                // Test basic operations
                try
                {
                    var tokens = await ListTokensAsync();
                    if (!tokens.Any())
                    {
                        issues.Add("No tokens found during health check");
                    }
                }
                catch (Exception ex)
                {
                    issues.Add($"Token enumeration failed: {ex.Message}");
                }

                stopwatch.Stop();

                if (issues.Count == 0)
                {
                    _logger.LogInformation("HSM health check passed in {ElapsedMs}ms", stopwatch.ElapsedMilliseconds);
                    return HsmHealthCheckResult.Healthy(stopwatch.Elapsed);
                }
                else
                {
                    _logger.LogWarning("HSM health check failed in {ElapsedMs}ms. Issues: {Issues}", 
                        stopwatch.ElapsedMilliseconds, string.Join(", ", issues));
                    return HsmHealthCheckResult.Unhealthy(issues, stopwatch.Elapsed);
                }
            }
            catch (Exception ex)
            {
                stopwatch.Stop();
                _logger.LogError(ex, "HSM health check failed with exception in {ElapsedMs}ms", stopwatch.ElapsedMilliseconds);
                issues.Add($"Health check exception: {ex.Message}");
                return HsmHealthCheckResult.Unhealthy(issues, stopwatch.Elapsed);
            }
        }

        /// <summary>
        /// Closes the HSM session and releases resources
        /// </summary>
        public async Task CloseAsync()
        {
            _logger.LogDebug("Closing HSM connection");

            try
            {
                // In a real implementation, this would:
                // 1. Call C_Logout if authenticated
                // 2. Call C_CloseSession
                // 3. Call C_Finalize

                _isAuthenticated = false;
                _isInitialized = false;
                _currentToken = null;

                lock (_sessionLock)
                {
                    _hsmKeys.Clear();
                }

                _logger.LogInformation("HSM connection closed successfully");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error closing HSM connection");
            }
        }

        protected virtual void Dispose(bool disposing)
        {
            if (disposing)
            {
                CloseAsync().GetAwaiter().GetResult();
            }
        }

        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}