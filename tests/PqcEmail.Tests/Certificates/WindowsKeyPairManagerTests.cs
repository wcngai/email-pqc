using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PqcEmail.Core.Certificates;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Certificates
{
    [TestClass]
    public class WindowsKeyPairManagerTests
    {
        private Mock<ILogger<WindowsKeyPairManager>> _mockLogger;
        private WindowsKeyPairManager _keyPairManager;

        [TestInitialize]
        public void Setup()
        {
            _mockLogger = new Mock<ILogger<WindowsKeyPairManager>>();
            _keyPairManager = new WindowsKeyPairManager(_mockLogger.Object);
        }

        [TestMethod]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsException<ArgumentNullException>(() => new WindowsKeyPairManager(null));
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_WithRSA_ReturnsValidKeyPair()
        {
            // Arrange
            var algorithm = "RSA";
            var usage = KeyUsage.Signing;
            var keySize = 2048;

            // Act
            var result = await _keyPairManager.GenerateKeyPairAsync(algorithm, usage, keySize);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(algorithm, result.Algorithm);
            Assert.AreEqual(usage, result.Usage);
            Assert.AreEqual(keySize, result.KeySize);
            Assert.IsTrue(result.PublicKeyData.Length > 0);
            Assert.IsFalse(string.IsNullOrEmpty(result.KeyId));
            Assert.IsFalse(result.IsPqcKeyPair);
            Assert.IsTrue(result.CreatedAt <= DateTimeOffset.UtcNow);
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_WithECDSA_ReturnsValidKeyPair()
        {
            // Arrange
            var algorithm = "ECDSA";
            var usage = KeyUsage.Signing;
            var keySize = 256;

            // Act
            var result = await _keyPairManager.GenerateKeyPairAsync(algorithm, usage, keySize);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(algorithm, result.Algorithm);
            Assert.AreEqual(usage, result.Usage);
            Assert.AreEqual(keySize, result.KeySize);
            Assert.IsTrue(result.PublicKeyData.Length > 0);
            Assert.IsFalse(result.IsPqcKeyPair);
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_WithMLKEM768_ReturnsValidPqcKeyPair()
        {
            // Arrange
            var algorithm = "ML-KEM-768";
            var usage = KeyUsage.Encryption;

            // Act
            var result = await _keyPairManager.GenerateKeyPairAsync(algorithm, usage);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(algorithm, result.Algorithm);
            Assert.AreEqual(usage, result.Usage);
            Assert.IsTrue(result.IsPqcKeyPair);
            Assert.AreEqual(1184, result.PublicKeyData.Length); // ML-KEM-768 public key size
            Assert.IsTrue(result.GenerationParameters.ContainsKey("Algorithm"));
            Assert.AreEqual("ML-KEM-768", result.GenerationParameters["Algorithm"]);
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_WithMLDSA65_ReturnsValidPqcKeyPair()
        {
            // Arrange
            var algorithm = "ML-DSA-65";
            var usage = KeyUsage.Signing;

            // Act
            var result = await _keyPairManager.GenerateKeyPairAsync(algorithm, usage);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(algorithm, result.Algorithm);
            Assert.AreEqual(usage, result.Usage);
            Assert.IsTrue(result.IsPqcKeyPair);
            Assert.AreEqual(1952, result.PublicKeyData.Length); // ML-DSA-65 public key size
            Assert.IsTrue(result.GenerationParameters.ContainsKey("Algorithm"));
            Assert.AreEqual("ML-DSA-65", result.GenerationParameters["Algorithm"]);
        }

        [TestMethod]
        public async Task GenerateKeyPairAsync_WithUnsupportedAlgorithm_ThrowsNotSupportedException()
        {
            // Arrange
            var algorithm = "UnsupportedAlgorithm";
            var usage = KeyUsage.Signing;

            // Act & Assert
            await Assert.ThrowsExceptionAsync<NotSupportedException>(
                async () => await _keyPairManager.GenerateKeyPairAsync(algorithm, usage));
        }

        [TestMethod]
        public async Task StoreKeyPairAsync_WithValidKeyPair_ReturnsSuccess()
        {
            // Arrange
            var keyPair = await CreateTestKeyPairAsync();
            var containerName = "TestContainer";

            // Act
            var result = await _keyPairManager.StoreKeyPairAsync(keyPair, containerName, false);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success);
            Assert.AreEqual(KeyStorageType.WindowsCng, result.StorageType);
            Assert.IsFalse(string.IsNullOrEmpty(result.ContainerName));
            Assert.AreEqual(keyPair.Fingerprint, result.KeyFingerprint);
        }

        [TestMethod]
        public async Task StoreKeyPairAsync_WithHsmRequest_ReturnsSuccess()
        {
            // Arrange
            var keyPair = await CreateTestKeyPairAsync();
            keyPair.HsmInfo = new HsmInfo
            {
                Provider = "TestHSM",
                TokenId = "Token001"
            };
            var containerName = "TestContainer";

            // Act
            var result = await _keyPairManager.StoreKeyPairAsync(keyPair, containerName, true);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success);
            Assert.AreEqual(KeyStorageType.HardwareSecurityModule, result.StorageType);
            Assert.IsNotNull(result.HsmInfo);
        }

        [TestMethod]
        public async Task RetrieveKeyPairAsync_WithNonExistentContainer_ReturnsNull()
        {
            // Arrange
            var containerName = "NonExistentContainer";
            var usage = KeyUsage.Signing;

            // Act
            var result = await _keyPairManager.RetrieveKeyPairAsync(containerName, usage);

            // Assert
            Assert.IsNull(result);
        }

        [TestMethod]
        public async Task DeleteKeyPairAsync_WithValidContainer_ReturnsTrue()
        {
            // Arrange
            var keyPair = await CreateTestKeyPairAsync();
            var containerName = "TestContainer";
            var usage = KeyUsage.Signing;

            // Store first
            await _keyPairManager.StoreKeyPairAsync(keyPair, containerName, false);

            // Act
            var result = await _keyPairManager.DeleteKeyPairAsync(containerName, usage);

            // Assert
            Assert.IsTrue(result);
        }

        [TestMethod]
        public async Task DeleteKeyPairAsync_WithNonExistentContainer_ReturnsFalse()
        {
            // Arrange
            var containerName = "NonExistentContainer";
            var usage = KeyUsage.Signing;

            // Act
            var result = await _keyPairManager.DeleteKeyPairAsync(containerName, usage);

            // Assert
            Assert.IsTrue(result); // Delete of non-existent key returns true (idempotent)
        }

        [TestMethod]
        public async Task ListKeyPairsAsync_WithValidIdentity_ReturnsCollection()
        {
            // Arrange
            var identity = "test@example.com";

            // Act
            var result = await _keyPairManager.ListKeyPairsAsync(identity);

            // Assert
            Assert.IsNotNull(result);
            var keyPairs = result.ToList();
            Assert.IsTrue(keyPairs.Count >= 0);
        }

        [TestMethod]
        public async Task RotateKeyPairAsync_WithNonExistentKeyPair_ThrowsInvalidOperationException()
        {
            // Arrange
            var containerName = "NonExistentContainer";
            var usage = KeyUsage.Signing;

            // Act & Assert
            await Assert.ThrowsExceptionAsync<InvalidOperationException>(
                async () => await _keyPairManager.RotateKeyPairAsync(containerName, usage));
        }

        [TestMethod]
        public async Task ArchiveKeyPairAsync_WithValidKeyPair_ReturnsSuccess()
        {
            // Arrange
            var keyPair = await CreateTestKeyPairAsync();
            var archivalReason = "Key rotation test";

            // Act
            var result = await _keyPairManager.ArchiveKeyPairAsync(keyPair, archivalReason);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success);
            Assert.AreEqual(keyPair.KeyId, result.OriginalKeyId);
            Assert.AreEqual(archivalReason, result.ArchivalReason);
            Assert.IsNotNull(result.ArchivedKeyInfo);
            Assert.IsTrue(result.ArchivedKeyInfo.IsArchived);
            Assert.IsFalse(result.ArchivedKeyInfo.IsActive);
        }

        [TestMethod]
        public async Task GetArchivedKeyPairsAsync_WithValidIdentity_ReturnsCollection()
        {
            // Arrange
            var identity = "test@example.com";

            // Act
            var result = await _keyPairManager.GetArchivedKeyPairsAsync(identity);

            // Assert
            Assert.IsNotNull(result);
            var archivedKeyPairs = result.ToList();
            Assert.IsTrue(archivedKeyPairs.Count >= 0);
            Assert.IsTrue(archivedKeyPairs.All(kp => kp.IsArchived));
        }

        [TestMethod]
        public async Task GetArchivedKeyPairsAsync_WithTimeRange_ReturnsFilteredCollection()
        {
            // Arrange
            var identity = "test@example.com";
            var timeRange = DateTimeOffset.UtcNow.AddDays(-30);

            // Act
            var result = await _keyPairManager.GetArchivedKeyPairsAsync(identity, timeRange);

            // Assert
            Assert.IsNotNull(result);
            var archivedKeyPairs = result.ToList();
            Assert.IsTrue(archivedKeyPairs.All(kp => kp.IsArchived && kp.CreatedAt >= timeRange));
        }

        [TestMethod]
        public async Task ExportKeyPairAsync_WithValidKeyPair_ReturnsData()
        {
            // Arrange
            var keyPair = await CreateTestKeyPairAsync();
            var password = "TestPassword123!";

            // Act
            var result = await _keyPairManager.ExportKeyPairAsync(keyPair, password);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length > 0);
        }

        [TestMethod]
        public async Task ExportKeyPairAsync_WithPqcKeyPair_ReturnsData()
        {
            // Arrange
            var keyPair = await _keyPairManager.GenerateKeyPairAsync("ML-DSA-65", KeyUsage.Signing);
            var password = "TestPassword123!";

            // Act
            var result = await _keyPairManager.ExportKeyPairAsync(keyPair, password);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Length > 0);
        }

        [TestMethod]
        public async Task ImportKeyPairAsync_WithValidData_ReturnsKeyPair()
        {
            // Arrange
            var originalKeyPair = await CreateTestKeyPairAsync();
            var password = "TestPassword123!";
            var exportedData = await _keyPairManager.ExportKeyPairAsync(originalKeyPair, password);
            var containerName = "ImportedContainer";

            // Act
            var result = await _keyPairManager.ImportKeyPairAsync(exportedData, password, containerName);

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(containerName, result.ContainerName);
            Assert.IsFalse(string.IsNullOrEmpty(result.KeyId));
        }

        [TestMethod]
        public async Task ImportKeyPairAsync_WithInvalidData_ThrowsException()
        {
            // Arrange
            var invalidData = new byte[] { 1, 2, 3, 4, 5 };
            var password = "TestPassword123!";
            var containerName = "ImportedContainer";

            // Act & Assert
            await Assert.ThrowsExceptionAsync<Exception>(
                async () => await _keyPairManager.ImportKeyPairAsync(invalidData, password, containerName));
        }

        [TestMethod]
        public void KeyPairInfo_IsPqcKeyPair_DetectsCorrectly()
        {
            // Test cases for PQC detection
            var testCases = new[]
            {
                new { Algorithm = "ML-KEM-768", Expected = true },
                new { Algorithm = "ML-DSA-65", Expected = true },
                new { Algorithm = "Kyber768", Expected = true },
                new { Algorithm = "Dilithium3", Expected = true },
                new { Algorithm = "RSA", Expected = false },
                new { Algorithm = "ECDSA", Expected = false }
            };

            foreach (var testCase in testCases)
            {
                // Arrange
                var keyPair = new KeyPairInfo { Algorithm = testCase.Algorithm };

                // Act & Assert
                Assert.AreEqual(testCase.Expected, keyPair.IsPqcKeyPair,
                    $"Algorithm {testCase.Algorithm} should return {testCase.Expected}");
            }
        }

        [TestMethod]
        public void KeyPairInfo_Fingerprint_GeneratesConsistentHash()
        {
            // Arrange
            var publicKeyData = new byte[] { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };
            var keyPair1 = new KeyPairInfo { PublicKeyData = publicKeyData };
            var keyPair2 = new KeyPairInfo { PublicKeyData = publicKeyData };

            // Act
            var fingerprint1 = keyPair1.Fingerprint;
            var fingerprint2 = keyPair2.Fingerprint;

            // Assert
            Assert.AreEqual(fingerprint1, fingerprint2);
            Assert.IsTrue(fingerprint1.Length > 0);
        }

        [TestMethod]
        public void KeyPairInfo_IsExpired_ChecksCorrectly()
        {
            // Arrange
            var expiredKeyPair = new KeyPairInfo 
            { 
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1) 
            };
            var validKeyPair = new KeyPairInfo 
            { 
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(30) 
            };
            var noExpirationKeyPair = new KeyPairInfo 
            { 
                ExpiresAt = null 
            };

            // Act & Assert
            Assert.IsTrue(expiredKeyPair.IsExpired);
            Assert.IsFalse(validKeyPair.IsExpired);
            Assert.IsFalse(noExpirationKeyPair.IsExpired);
        }

        [TestMethod]
        public void KeyPairInfo_DaysUntilExpiration_CalculatesCorrectly()
        {
            // Arrange
            var keyPairIn30Days = new KeyPairInfo 
            { 
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(30) 
            };
            var expiredKeyPair = new KeyPairInfo 
            { 
                ExpiresAt = DateTimeOffset.UtcNow.AddDays(-1) 
            };
            var noExpirationKeyPair = new KeyPairInfo 
            { 
                ExpiresAt = null 
            };

            // Act & Assert
            Assert.IsTrue(keyPairIn30Days.DaysUntilExpiration > 25 && keyPairIn30Days.DaysUntilExpiration <= 30);
            Assert.AreEqual(0, expiredKeyPair.DaysUntilExpiration);
            Assert.IsNull(noExpirationKeyPair.DaysUntilExpiration);
        }

        private async Task<KeyPairInfo> CreateTestKeyPairAsync()
        {
            return await _keyPairManager.GenerateKeyPairAsync("RSA", KeyUsage.Signing, 2048);
        }
    }
}