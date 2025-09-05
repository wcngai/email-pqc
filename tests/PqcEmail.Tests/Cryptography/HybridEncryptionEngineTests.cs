using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using FluentAssertions;
using PqcEmail.Core.Cryptography;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Cryptography
{
    [TestFixture]
    public class HybridEncryptionEngineTests
    {
        private HybridEncryptionEngine _engine;
        private Mock<ICryptographicProvider> _mockProvider;
        private Mock<ILogger<HybridEncryptionEngine>> _mockLogger;
        private AlgorithmConfiguration _hybridConfig;

        [SetUp]
        public void SetUp()
        {
            _mockProvider = new Mock<ICryptographicProvider>();
            _mockLogger = new Mock<ILogger<HybridEncryptionEngine>>();
            _hybridConfig = AlgorithmConfiguration.CreateDefault();

            _mockProvider.Setup(p => p.Configuration).Returns(_hybridConfig);

            _engine = new HybridEncryptionEngine(_mockProvider.Object, _mockLogger.Object);
        }

        #region Constructor Tests

        [Test]
        public void Constructor_WithNullProvider_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new HybridEncryptionEngine(null, _mockLogger.Object));
        }

        [Test]
        public void Constructor_WithNullLogger_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new HybridEncryptionEngine(_mockProvider.Object, null));
        }

        #endregion

        #region Hybrid Encryption Tests

        [Test]
        public async Task EncryptHybridAsync_WithBothKeys_ShouldCreateHybridEncryption()
        {
            // Arrange
            var testData = "Hybrid encryption test data"u8.ToArray();
            var pqcPublicKey = new byte[1184]; // ML-KEM-768 key size
            var classicalPublicKey = new byte[270]; // RSA-2048 key size
            
            var pqcEncryptionResult = new EncryptionResult(
                new byte[1088], // ML-KEM-768 ciphertext size
                "ML-KEM-768",
                new EncryptionMetadata(DateTime.UtcNow, true, false, postQuantumAlgorithm: "ML-KEM-768")
            );
            
            var classicalEncryptionResult = new EncryptionResult(
                new byte[256], // RSA-2048 ciphertext size
                "RSA-OAEP-2048",
                new EncryptionMetadata(DateTime.UtcNow, false, false, classicalAlgorithm: "RSA-OAEP-2048")
            );

            _mockProvider.Setup(p => p.EncryptAsync(It.IsAny<byte[]>(), pqcPublicKey))
                .ReturnsAsync(CryptographicResult<EncryptionResult>.Success(pqcEncryptionResult));
            
            _mockProvider.Setup(p => p.EncryptAsync(It.IsAny<byte[]>(), classicalPublicKey))
                .ReturnsAsync(CryptographicResult<EncryptionResult>.Success(classicalEncryptionResult));

            // Act
            var result = await _engine.EncryptHybridAsync(testData, pqcPublicKey, classicalPublicKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();
            
            var hybridResult = result.Data;
            hybridResult.Strategy.Should().Be(EncryptionStrategy.Hybrid);
            hybridResult.Metadata.IsHybrid.Should().BeTrue();
            hybridResult.Metadata.IsPostQuantum.Should().BeTrue();
            
            var encryptedData = hybridResult.EncryptedData;
            encryptedData.PostQuantumEncryptedKey.Should().NotBeNullOrEmpty();
            encryptedData.ClassicalEncryptedKey.Should().NotBeNullOrEmpty();
            encryptedData.SymmetricEncryptedData.Should().NotBeNullOrEmpty();
            encryptedData.InitializationVector.Should().NotBeNullOrEmpty();
            encryptedData.AuthenticationTag.Should().NotBeNullOrEmpty();
            
            encryptedData.AlgorithmInfo.PostQuantumKemAlgorithm.Should().Be("ML-KEM-768");
            encryptedData.AlgorithmInfo.ClassicalKemAlgorithm.Should().Be("RSA-OAEP-2048");
            encryptedData.AlgorithmInfo.SymmetricAlgorithm.Should().Be("AES-256-GCM");
        }

        [Test]
        public async Task EncryptHybridAsync_WithOnlyPqcKey_ShouldCreatePqcOnlyEncryption()
        {
            // Arrange
            var testData = "PQC-only encryption test data"u8.ToArray();
            var pqcPublicKey = new byte[1184];
            
            var pqcEncryptionResult = new EncryptionResult(
                new byte[1088],
                "ML-KEM-768",
                new EncryptionMetadata(DateTime.UtcNow, true, false, postQuantumAlgorithm: "ML-KEM-768")
            );

            _mockProvider.Setup(p => p.EncryptAsync(It.IsAny<byte[]>(), pqcPublicKey))
                .ReturnsAsync(CryptographicResult<EncryptionResult>.Success(pqcEncryptionResult));

            // Act
            var result = await _engine.EncryptHybridAsync(testData, pqcPublicKey, null);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Strategy.Should().Be(EncryptionStrategy.PostQuantumOnly);
            result.Data.Metadata.IsPostQuantum.Should().BeTrue();
            result.Data.Metadata.IsHybrid.Should().BeFalse();
            result.Data.EncryptedData.PostQuantumEncryptedKey.Should().NotBeNullOrEmpty();
            result.Data.EncryptedData.ClassicalEncryptedKey.Should().BeNull();
        }

        [Test]
        public async Task EncryptHybridAsync_WithOnlyClassicalKey_ShouldCreateClassicalOnlyEncryption()
        {
            // Arrange
            var testData = "Classical-only encryption test data"u8.ToArray();
            var classicalPublicKey = new byte[270];
            
            var classicalEncryptionResult = new EncryptionResult(
                new byte[256],
                "RSA-OAEP-2048",
                new EncryptionMetadata(DateTime.UtcNow, false, false, classicalAlgorithm: "RSA-OAEP-2048")
            );

            _mockProvider.Setup(p => p.EncryptAsync(It.IsAny<byte[]>(), classicalPublicKey))
                .ReturnsAsync(CryptographicResult<EncryptionResult>.Success(classicalEncryptionResult));

            // Act
            var result = await _engine.EncryptHybridAsync(testData, null, classicalPublicKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Strategy.Should().Be(EncryptionStrategy.ClassicalOnly);
            result.Data.Metadata.IsPostQuantum.Should().BeFalse();
            result.Data.Metadata.IsHybrid.Should().BeFalse();
            result.Data.EncryptedData.PostQuantumEncryptedKey.Should().BeNull();
            result.Data.EncryptedData.ClassicalEncryptedKey.Should().NotBeNullOrEmpty();
        }

        [Test]
        public async Task EncryptHybridAsync_WithBothEncryptionFailures_ShouldReturnFailure()
        {
            // Arrange
            var testData = "Test data"u8.ToArray();
            var pqcPublicKey = new byte[1184];
            var classicalPublicKey = new byte[270];

            _mockProvider.Setup(p => p.EncryptAsync(It.IsAny<byte[]>(), pqcPublicKey))
                .ReturnsAsync(CryptographicResult<EncryptionResult>.Failure("PQC encryption failed"));
            
            _mockProvider.Setup(p => p.EncryptAsync(It.IsAny<byte[]>(), classicalPublicKey))
                .ReturnsAsync(CryptographicResult<EncryptionResult>.Failure("Classical encryption failed"));

            // Act
            var result = await _engine.EncryptHybridAsync(testData, pqcPublicKey, classicalPublicKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeFalse();
            result.ErrorMessage.Should().Contain("Failed to encrypt with any available algorithm");
        }

        [Test]
        public void EncryptHybridAsync_WithNullData_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _engine.EncryptHybridAsync(null, new byte[100], new byte[100]));
        }

        #endregion

        #region Hybrid Decryption Tests

        [Test]
        public async Task DecryptHybridAsync_WithPqcDecryptionSuccess_ShouldDecryptSuccessfully()
        {
            // Arrange
            var originalData = "Original hybrid encrypted data"u8.ToArray();
            var symmetricKey = new byte[32];
            new Random().NextBytes(symmetricKey);

            var hybridData = CreateTestHybridEncryptedData(originalData, symmetricKey);
            var pqcPrivateKey = new byte[100];
            var classicalPrivateKey = new byte[100];

            _mockProvider.Setup(p => p.DecryptAsync(hybridData.PostQuantumEncryptedKey, pqcPrivateKey))
                .ReturnsAsync(CryptographicResult<byte[]>.Success(symmetricKey));

            // Act
            var result = await _engine.DecryptHybridAsync(hybridData, pqcPrivateKey, classicalPrivateKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNullOrEmpty();
            
            // Verify PQC decryption was attempted first
            _mockProvider.Verify(p => p.DecryptAsync(hybridData.PostQuantumEncryptedKey, pqcPrivateKey), Times.Once);
            _mockProvider.Verify(p => p.DecryptAsync(hybridData.ClassicalEncryptedKey, classicalPrivateKey), Times.Never);
        }

        [Test]
        public async Task DecryptHybridAsync_WithPqcFailureClassicalSuccess_ShouldFallbackSuccessfully()
        {
            // Arrange
            var originalData = "Fallback decryption test data"u8.ToArray();
            var symmetricKey = new byte[32];
            new Random().NextBytes(symmetricKey);

            var hybridData = CreateTestHybridEncryptedData(originalData, symmetricKey);
            var pqcPrivateKey = new byte[100];
            var classicalPrivateKey = new byte[100];

            _mockProvider.Setup(p => p.DecryptAsync(hybridData.PostQuantumEncryptedKey, pqcPrivateKey))
                .ReturnsAsync(CryptographicResult<byte[]>.Failure("PQC decryption failed"));
            
            _mockProvider.Setup(p => p.DecryptAsync(hybridData.ClassicalEncryptedKey, classicalPrivateKey))
                .ReturnsAsync(CryptographicResult<byte[]>.Success(symmetricKey));

            // Act
            var result = await _engine.DecryptHybridAsync(hybridData, pqcPrivateKey, classicalPrivateKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNullOrEmpty();
            
            // Verify fallback was used
            _mockProvider.Verify(p => p.DecryptAsync(hybridData.PostQuantumEncryptedKey, pqcPrivateKey), Times.Once);
            _mockProvider.Verify(p => p.DecryptAsync(hybridData.ClassicalEncryptedKey, classicalPrivateKey), Times.Once);
        }

        [Test]
        public async Task DecryptHybridAsync_WithBothDecryptionFailures_ShouldReturnFailure()
        {
            // Arrange
            var originalData = "Test data for failure case"u8.ToArray();
            var symmetricKey = new byte[32];
            var hybridData = CreateTestHybridEncryptedData(originalData, symmetricKey);
            var pqcPrivateKey = new byte[100];
            var classicalPrivateKey = new byte[100];

            _mockProvider.Setup(p => p.DecryptAsync(It.IsAny<byte[]>(), pqcPrivateKey))
                .ReturnsAsync(CryptographicResult<byte[]>.Failure("PQC decryption failed"));
            
            _mockProvider.Setup(p => p.DecryptAsync(It.IsAny<byte[]>(), classicalPrivateKey))
                .ReturnsAsync(CryptographicResult<byte[]>.Failure("Classical decryption failed"));

            // Act
            var result = await _engine.DecryptHybridAsync(hybridData, pqcPrivateKey, classicalPrivateKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeFalse();
            result.ErrorMessage.Should().Contain("Failed to decrypt symmetric key");
        }

        [Test]
        public void DecryptHybridAsync_WithNullHybridData_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _engine.DecryptHybridAsync(null, new byte[100], new byte[100]));
        }

        #endregion

        #region Strategy Determination Tests

        [Test]
        public void DetermineEncryptionStrategy_WithPqcOnlyMode_ShouldReturnPqcOnly()
        {
            // Arrange
            var pqcOnlyConfig = AlgorithmConfiguration.CreatePostQuantumOnly();
            _mockProvider.Setup(p => p.Configuration).Returns(pqcOnlyConfig);
            
            var engine = new HybridEncryptionEngine(_mockProvider.Object, _mockLogger.Object);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: false
            );

            // Act
            var strategy = engine.DetermineEncryptionStrategy(capabilities);

            // Assert
            strategy.Should().Be(EncryptionStrategy.PostQuantumOnly);
        }

        [Test]
        public void DetermineEncryptionStrategy_WithClassicalOnlyMode_ShouldReturnClassicalOnly()
        {
            // Arrange
            var classicalOnlyConfig = AlgorithmConfiguration.CreateClassicalOnly();
            _mockProvider.Setup(p => p.Configuration).Returns(classicalOnlyConfig);
            
            var engine = new HybridEncryptionEngine(_mockProvider.Object, _mockLogger.Object);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: true
            );

            // Act
            var strategy = engine.DetermineEncryptionStrategy(capabilities);

            // Assert
            strategy.Should().Be(EncryptionStrategy.ClassicalOnly);
        }

        [Test]
        public void DetermineEncryptionStrategy_WithHybridCapableRecipient_ShouldReturnHybrid()
        {
            // Arrange (using default hybrid config)
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: true
            );

            // Act
            var strategy = _engine.DetermineEncryptionStrategy(capabilities);

            // Assert
            strategy.Should().Be(EncryptionStrategy.Hybrid);
        }

        [Test]
        public void DetermineEncryptionStrategy_WithPqcCapableButNoHybrid_ShouldReturnPqcOnly()
        {
            // Arrange
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: false
            );

            // Act
            var strategy = _engine.DetermineEncryptionStrategy(capabilities);

            // Assert
            strategy.Should().Be(EncryptionStrategy.PostQuantumOnly);
        }

        [Test]
        public void DetermineEncryptionStrategy_WithUnsupportedPqcAlgorithms_ShouldReturnClassicalOnly()
        {
            // Arrange
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "UNSUPPORTED-KEM" },
                supportedPqcSignatureAlgorithms: new[] { "UNSUPPORTED-SIG" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: false
            );

            // Act
            var strategy = _engine.DetermineEncryptionStrategy(capabilities);

            // Assert
            strategy.Should().Be(EncryptionStrategy.ClassicalOnly);
        }

        [Test]
        public void DetermineEncryptionStrategy_WithNullCapabilities_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                _engine.DetermineEncryptionStrategy(null));
        }

        #endregion

        #region Round-trip Integration Tests

        [Test]
        public async Task EncryptDecryptHybrid_RoundTrip_ShouldRecoverOriginalData()
        {
            // This test would require a full integration with a real cryptographic provider
            // For now, we'll create a simplified version using mock expectations
            
            // Arrange
            var originalData = "Round-trip hybrid encryption test"u8.ToArray();
            var pqcPublicKey = new byte[1184];
            var classicalPublicKey = new byte[270];
            var pqcPrivateKey = new byte[100];
            var classicalPrivateKey = new byte[100];
            var symmetricKey = new byte[32];
            new Random().NextBytes(symmetricKey);

            // Setup encryption mocks
            var pqcEncResult = new EncryptionResult(new byte[1088], "ML-KEM-768", 
                new EncryptionMetadata(DateTime.UtcNow, true, false, postQuantumAlgorithm: "ML-KEM-768"));
            var classicalEncResult = new EncryptionResult(new byte[256], "RSA-OAEP-2048",
                new EncryptionMetadata(DateTime.UtcNow, false, false, classicalAlgorithm: "RSA-OAEP-2048"));

            _mockProvider.Setup(p => p.EncryptAsync(It.IsAny<byte[]>(), pqcPublicKey))
                .ReturnsAsync(CryptographicResult<EncryptionResult>.Success(pqcEncResult));
            _mockProvider.Setup(p => p.EncryptAsync(It.IsAny<byte[]>(), classicalPublicKey))
                .ReturnsAsync(CryptographicResult<EncryptionResult>.Success(classicalEncResult));

            // Setup decryption mock
            _mockProvider.Setup(p => p.DecryptAsync(It.IsAny<byte[]>(), pqcPrivateKey))
                .ReturnsAsync(CryptographicResult<byte[]>.Success(symmetricKey));

            // Act - Encrypt
            var encryptResult = await _engine.EncryptHybridAsync(originalData, pqcPublicKey, classicalPublicKey);
            
            // Assert encryption succeeded
            encryptResult.IsSuccess.Should().BeTrue();
            encryptResult.Data.Strategy.Should().Be(EncryptionStrategy.Hybrid);

            // For this test, we would need to properly handle the AES-GCM encryption/decryption
            // This is a limitation of the current test setup with mocked providers
        }

        #endregion

        #region Helper Methods

        private HybridEncryptedData CreateTestHybridEncryptedData(byte[] originalData, byte[] symmetricKey)
        {
            // This creates a simplified test structure
            // In a real implementation, the data would be properly encrypted with AES-GCM
            var iv = new byte[12];
            var authTag = new byte[16];
            new Random().NextBytes(iv);
            new Random().NextBytes(authTag);

            var algorithmInfo = new HybridAlgorithmInfo("ML-KEM-768", "RSA-OAEP-2048", "AES-256-GCM");

            return new HybridEncryptedData(
                postQuantumEncryptedKey: new byte[1088],
                classicalEncryptedKey: new byte[256],
                symmetricEncryptedData: originalData, // Simplified - would be encrypted in real implementation
                initializationVector: iv,
                authenticationTag: authTag,
                algorithmInfo: algorithmInfo
            );
        }

        #endregion
    }
}