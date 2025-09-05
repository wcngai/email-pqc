using System;
using System.Linq;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PqcEmail.Core.Certificates;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Certificates
{
    [TestClass]
    public class Pkcs11HsmProviderTests
    {
        private Mock<ILogger<Pkcs11HsmProvider>> _mockLogger;
        private Pkcs11HsmProvider _hsmProvider;

        [TestInitialize]
        public void Setup()
        {
            _mockLogger = new Mock<ILogger<Pkcs11HsmProvider>>();
            _hsmProvider = new Pkcs11HsmProvider(_mockLogger.Object);
        }

        [TestCleanup]
        public async Task Cleanup()
        {
            if (_hsmProvider.IsConnected)
            {
                await _hsmProvider.CloseAsync();
            }
            _hsmProvider?.Dispose();
        }

        [TestMethod]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsException<ArgumentNullException>(() => new Pkcs11HsmProvider(null));
        }

        [TestMethod]
        public void IsConnected_InitialState_ReturnsFalse()
        {
            // Act & Assert
            Assert.IsFalse(_hsmProvider.IsConnected);
        }

        [TestMethod]
        public void CurrentToken_InitialState_ReturnsNull()
        {
            // Act & Assert
            Assert.IsNull(_hsmProvider.CurrentToken);
        }

        [TestMethod]
        public async Task InitializeAsync_WithValidParameters_ReturnsTrue()
        {
            // Arrange
            var libraryPath = "/usr/lib/libpkcs11.so";
            var tokenLabel = "TestToken";

            // Act
            var result = await _hsmProvider.InitializeAsync(libraryPath, tokenLabel);

            // Assert
            Assert.IsTrue(result);
            Assert.IsNotNull(_hsmProvider.CurrentToken);
            Assert.AreEqual(tokenLabel, _hsmProvider.CurrentToken.Label);
        }

        [TestMethod]
        public async Task AuthenticateAsync_WithValidPin_ReturnsSuccess()
        {
            // Arrange
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");
            var pin = "123456";

            // Act
            var result = await _hsmProvider.AuthenticateAsync(pin);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success);
            Assert.AreEqual(HsmAuthMethod.Pin, result.AuthMethod);
            Assert.IsNotNull(result.SessionTimeout);
            Assert.IsTrue(_hsmProvider.IsConnected);
        }

        [TestMethod]
        public async Task AuthenticateAsync_WithInvalidPin_ReturnsFailure()
        {
            // Arrange
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");
            var invalidPin = "123"; // Too short

            // Act
            var result = await _hsmProvider.AuthenticateAsync(invalidPin);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsFalse(result.Success);
            Assert.IsNotNull(result.ErrorMessage);
            Assert.IsFalse(_hsmProvider.IsConnected);
        }

        [TestMethod]
        public async Task AuthenticateAsync_WithoutInitialization_ReturnsFailure()
        {
            // Arrange
            var pin = "123456";

            // Act
            var result = await _hsmProvider.AuthenticateAsync(pin);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsFalse(result.Success);
            Assert.IsTrue(result.ErrorMessage.Contains("not initialized"));
        }

        [TestMethod]
        public async Task ListTokensAsync_AfterInitialization_ReturnsTokens()
        {
            // Arrange
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");

            // Act
            var result = await _hsmProvider.ListTokensAsync();

            // Assert
            Assert.IsNotNull(result);
            var tokens = result.ToList();
            Assert.IsTrue(tokens.Count > 0);
            Assert.IsTrue(tokens.Any(t => t.Label == "TestToken"));
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_WithRSA_ReturnsValidKeyPair()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            var algorithm = "RSA";
            var keySize = 2048;
            var keyLabel = "TestRSAKey";
            var usage = KeyUsage.Signing;

            // Act
            var result = await _hsmProvider.GenerateKeyPairAsync(algorithm, keySize, keyLabel, usage);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(keyLabel, result.KeyLabel);
            Assert.AreEqual(algorithm, result.Algorithm);
            Assert.AreEqual(keySize, result.KeySize);
            Assert.AreEqual(usage, result.Usage);
            Assert.IsTrue(result.IsPrivate);
            Assert.IsFalse(result.IsExtractable);
            Assert.IsTrue(result.PublicKeyData.Length > 0);
            Assert.IsNotNull(result.Token);
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_WithMLKEM768_ReturnsValidPqcKeyPair()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            var algorithm = "ML-KEM-768";
            var keySize = 768;
            var keyLabel = "TestMLKEMKey";
            var usage = KeyUsage.Encryption;

            // Act
            var result = await _hsmProvider.GenerateKeyPairAsync(algorithm, keySize, keyLabel, usage);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(keyLabel, result.KeyLabel);
            Assert.AreEqual(algorithm, result.Algorithm);
            Assert.AreEqual(keySize, result.KeySize);
            Assert.AreEqual(usage, result.Usage);
            Assert.AreEqual(1184, result.PublicKeyData.Length); // ML-KEM-768 public key size
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_WithMLDSA65_ReturnsValidPqcKeyPair()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            var algorithm = "ML-DSA-65";
            var keySize = 65;
            var keyLabel = "TestMLDSAKey";
            var usage = KeyUsage.Signing;

            // Act
            var result = await _hsmProvider.GenerateKeyPairAsync(algorithm, keySize, keyLabel, usage);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(keyLabel, result.KeyLabel);
            Assert.AreEqual(algorithm, result.Algorithm);
            Assert.AreEqual(keySize, result.KeySize);
            Assert.AreEqual(usage, result.Usage);
            Assert.AreEqual(1952, result.PublicKeyData.Length); // ML-DSA-65 public key size
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_WithoutAuthentication_ThrowsException()
        {
            // Arrange
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");
            // Not authenticated

            // Act & Assert
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(
                async () => await _hsmProvider.GenerateKeyPairAsync("RSA", 2048, "TestKey", KeyUsage.Signing));
        }

        [TestMethod]
        public async Task StoreKeyPairAsync_WithValidKeyPair_ReturnsSuccess()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            var keyPair = CreateTestKeyPairInfo();
            var keyLabel = "StoredTestKey";

            // Act
            var result = await _hsmProvider.StoreKeyPairAsync(keyPair, keyLabel);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success);
            Assert.AreEqual(keyLabel, result.KeyLabel);
            Assert.AreEqual(keyPair.KeyId, result.KeyId);
        }

        [TestMethod]
        public async Task StoreKeyPairAsync_WithoutAuthentication_ReturnsFailure()
        {
            // Arrange
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");
            var keyPair = CreateTestKeyPairInfo();
            var keyLabel = "TestKey";

            // Act
            var result = await _hsmProvider.StoreKeyPairAsync(keyPair, keyLabel);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsFalse(result.Success);
            Assert.IsNotNull(result.ErrorMessage);
        }

        [TestMethod]
        public async Task RetrieveKeyPairAsync_WithExistingKey_ReturnsKeyPair()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            var keyPair = await _hsmProvider.GenerateKeyPairAsync("RSA", 2048, "RetrieveTestKey", KeyUsage.Signing);

            // Act
            var result = await _hsmProvider.RetrieveKeyPairAsync("RetrieveTestKey");

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("RetrieveTestKey", result.KeyLabel);
            Assert.AreEqual(keyPair.Algorithm, result.Algorithm);
        }

        [TestMethod]
        public async Task RetrieveKeyPairAsync_WithNonExistentKey_ReturnsNull()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();

            // Act
            var result = await _hsmProvider.RetrieveKeyPairAsync("NonExistentKey");

            // Assert
            Assert.IsNull(result);
        }

        [TestMethod]
        public async Task DeleteKeyPairAsync_WithExistingKey_ReturnsTrue()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            await _hsmProvider.GenerateKeyPairAsync("RSA", 2048, "DeleteTestKey", KeyUsage.Signing);

            // Act
            var result = await _hsmProvider.DeleteKeyPairAsync("DeleteTestKey");

            // Assert
            Assert.IsTrue(result);

            // Verify key is deleted
            var retrievedKey = await _hsmProvider.RetrieveKeyPairAsync("DeleteTestKey");
            Assert.IsNull(retrievedKey);
        }

        [TestMethod]
        public async Task DeleteKeyPairAsync_WithNonExistentKey_ReturnsFalse()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();

            // Act
            var result = await _hsmProvider.DeleteKeyPairAsync("NonExistentKey");

            // Assert
            Assert.IsFalse(result);
        }

        [TestMethod]
        public async Task ListKeyPairsAsync_WithStoredKeys_ReturnsKeyPairs()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            await _hsmProvider.GenerateKeyPairAsync("RSA", 2048, "ListTestKey1", KeyUsage.Signing);
            await _hsmProvider.GenerateKeyPairAsync("ECDSA", 256, "ListTestKey2", KeyUsage.Signing);

            // Act
            var result = await _hsmProvider.ListKeyPairsAsync();

            // Assert
            Assert.IsNotNull(result);
            var keyPairs = result.ToList();
            Assert.IsTrue(keyPairs.Count >= 2);
            Assert.IsTrue(keyPairs.Any(kp => kp.KeyLabel == "ListTestKey1"));
            Assert.IsTrue(keyPairs.Any(kp => kp.KeyLabel == "ListTestKey2"));
        }

        [TestMethod]
        public async Task SignAsync_WithValidKey_ReturnsSignature()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            var keyPair = await _hsmProvider.GenerateKeyPairAsync("RSA", 2048, "SignTestKey", KeyUsage.Signing);
            var data = System.Text.Encoding.UTF8.GetBytes("Test data to sign");

            // Act
            var result = await _hsmProvider.SignAsync("SignTestKey", data, HashAlgorithmName.SHA256);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length > 0);
        }

        [TestMethod]
        public async Task SignAsync_WithEncryptionKey_ThrowsException()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            await _hsmProvider.GenerateKeyPairAsync("RSA", 2048, "EncryptTestKey", KeyUsage.Encryption);
            var data = System.Text.Encoding.UTF8.GetBytes("Test data to sign");

            // Act & Assert
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(
                async () => await _hsmProvider.SignAsync("EncryptTestKey", data, HashAlgorithmName.SHA256));
        }

        [TestMethod]
        public async Task SignAsync_WithNonExistentKey_ThrowsException()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            var data = System.Text.Encoding.UTF8.GetBytes("Test data to sign");

            // Act & Assert
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(
                async () => await _hsmProvider.SignAsync("NonExistentKey", data, HashAlgorithmName.SHA256));
        }

        [TestMethod]
        public async Task VerifySignatureAsync_WithValidSignature_ReturnsTrue()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            var keyPair = await _hsmProvider.GenerateKeyPairAsync("RSA", 2048, "VerifyTestKey", KeyUsage.Signing);
            var data = System.Text.Encoding.UTF8.GetBytes("Test data to sign");
            var signature = await _hsmProvider.SignAsync("VerifyTestKey", data, HashAlgorithmName.SHA256);

            // Act
            var result = await _hsmProvider.VerifySignatureAsync("VerifyTestKey", data, signature, HashAlgorithmName.SHA256);

            // Assert
            Assert.IsTrue(result);
        }

        [TestMethod]
        public async Task EncapsulateAsync_WithMLKEMKey_ReturnsValidResult()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            var keyPair = await _hsmProvider.GenerateKeyPairAsync("ML-KEM-768", 768, "KEMTestKey", KeyUsage.Encryption);
            var sharedSecretLength = 32;

            // Act
            var result = await _hsmProvider.EncapsulateAsync("KEMTestKey", sharedSecretLength);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(1088, result.Ciphertext.Length); // ML-KEM-768 ciphertext size
            Assert.AreEqual(sharedSecretLength, result.SharedSecret.Length);
            Assert.AreEqual("ML-KEM-768", result.Algorithm);
        }

        [TestMethod]
        public async Task EncapsulateAsync_WithNonKEMKey_ThrowsException()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            await _hsmProvider.GenerateKeyPairAsync("RSA", 2048, "RSATestKey", KeyUsage.Encryption);

            // Act & Assert
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(
                async () => await _hsmProvider.EncapsulateAsync("RSATestKey", 32));
        }

        [TestMethod]
        public async Task DecapsulateAsync_WithValidCiphertext_ReturnsSharedSecret()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            var keyPair = await _hsmProvider.GenerateKeyPairAsync("ML-KEM-768", 768, "DecapTestKey", KeyUsage.Encryption);
            var encapsulationResult = await _hsmProvider.EncapsulateAsync("DecapTestKey", 32);

            // Act
            var result = await _hsmProvider.DecapsulateAsync("DecapTestKey", encapsulationResult.Ciphertext);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(32, result.Length);
        }

        [TestMethod]
        public async Task EncryptAsync_WithValidKey_ReturnsEncryptedData()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            await _hsmProvider.GenerateKeyPairAsync("RSA", 2048, "CryptTestKey", KeyUsage.Encryption);
            var plaintext = System.Text.Encoding.UTF8.GetBytes("Secret message");

            // Act
            var result = await _hsmProvider.EncryptAsync("CryptTestKey", plaintext, "AES-GCM");

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length > plaintext.Length); // Should include authentication tag
        }

        [TestMethod]
        public async Task DecryptAsync_WithValidCiphertext_ReturnsPlaintext()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            await _hsmProvider.GenerateKeyPairAsync("RSA", 2048, "DecryptTestKey", KeyUsage.Encryption);
            var plaintext = System.Text.Encoding.UTF8.GetBytes("Secret message");
            var ciphertext = await _hsmProvider.EncryptAsync("DecryptTestKey", plaintext, "AES-GCM");

            // Act
            var result = await _hsmProvider.DecryptAsync("DecryptTestKey", ciphertext, "AES-GCM");

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(plaintext.Length, result.Length);
            CollectionAssert.AreEqual(plaintext, result);
        }

        [TestMethod]
        public async Task GetTokenInfoAsync_WithValidToken_ReturnsTokenInfo()
        {
            // Arrange
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");

            // Act
            var result = await _hsmProvider.GetTokenInfoAsync("TestToken");

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("TestToken", result.Label);
            Assert.IsTrue(result.SupportedMechanisms.Count > 0);
        }

        [TestMethod]
        public async Task GetTokenInfoAsync_WithInvalidToken_ReturnsNull()
        {
            // Arrange
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");

            // Act
            var result = await _hsmProvider.GetTokenInfoAsync("InvalidToken");

            // Assert
            Assert.IsNull(result);
        }

        [TestMethod]
        public async Task GetMechanismInfoAsync_WithSupportedMechanism_ReturnsInfo()
        {
            // Arrange
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");

            // Act
            var result = await _hsmProvider.GetMechanismInfoAsync("CKM_RSA_PKCS");

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("CKM_RSA_PKCS", result.MechanismType);
            Assert.IsTrue(result.SupportsSignature);
            Assert.IsTrue(result.SupportsVerify);
        }

        [TestMethod]
        public async Task GetMechanismInfoAsync_WithUnsupportedMechanism_ReturnsNull()
        {
            // Arrange
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");

            // Act
            var result = await _hsmProvider.GetMechanismInfoAsync("CKM_UNSUPPORTED");

            // Assert
            Assert.IsNull(result);
        }

        [TestMethod]
        public async Task PerformHealthCheckAsync_WithHealthyHsm_ReturnsHealthy()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();

            // Act
            var result = await _hsmProvider.PerformHealthCheckAsync();

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.IsHealthy);
            Assert.AreEqual("Healthy", result.Status);
            Assert.AreEqual(0, result.Issues.Count);
            Assert.IsTrue(result.ResponseTime.TotalMilliseconds >= 0);
        }

        [TestMethod]
        public async Task PerformHealthCheckAsync_WithoutAuthentication_ReturnsUnhealthy()
        {
            // Arrange
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");

            // Act
            var result = await _hsmProvider.PerformHealthCheckAsync();

            // Assert
            Assert.IsNotNull(result);
            Assert.IsFalse(result.IsHealthy);
            Assert.IsTrue(result.Issues.Count > 0);
            Assert.IsTrue(result.Issues.Any(issue => issue.Contains("not authenticated")));
        }

        [TestMethod]
        public async Task CloseAsync_AfterConnection_DisconnectsSuccessfully()
        {
            // Arrange
            await InitializeAndAuthenticateAsync();
            Assert.IsTrue(_hsmProvider.IsConnected);

            // Act
            await _hsmProvider.CloseAsync();

            // Assert
            Assert.IsFalse(_hsmProvider.IsConnected);
            Assert.IsNull(_hsmProvider.CurrentToken);
        }

        private async Task InitializeAndAuthenticateAsync()
        {
            await _hsmProvider.InitializeAsync("/usr/lib/libpkcs11.so", "TestToken");
            var authResult = await _hsmProvider.AuthenticateAsync("123456");
            Assert.IsTrue(authResult.Success, "Authentication should succeed");
        }

        private KeyPairInfo CreateTestKeyPairInfo()
        {
            return new KeyPairInfo
            {
                KeyId = Guid.NewGuid().ToString(),
                Algorithm = "RSA",
                Usage = KeyUsage.Signing,
                KeySize = 2048,
                PublicKeyData = new byte[256],
                Identity = "test@example.com"
            };
        }
    }
}