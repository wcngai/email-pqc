using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using NUnit.Framework;
using FluentAssertions;
using PqcEmail.Core.Cryptography;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Cryptography
{
    [TestFixture]
    public class BouncyCastleCryptographicProviderTests
    {
        private BouncyCastleCryptographicProvider _provider;
        private Mock<ILogger<BouncyCastleCryptographicProvider>> _mockLogger;
        private AlgorithmConfiguration _hybridConfig;
        private AlgorithmConfiguration _pqcOnlyConfig;
        private AlgorithmConfiguration _classicalOnlyConfig;

        [SetUp]
        public void SetUp()
        {
            _mockLogger = new Mock<ILogger<BouncyCastleCryptographicProvider>>();
            
            _hybridConfig = AlgorithmConfiguration.CreateDefault();
            _pqcOnlyConfig = AlgorithmConfiguration.CreatePostQuantumOnly();
            _classicalOnlyConfig = AlgorithmConfiguration.CreateClassicalOnly();

            _provider = new BouncyCastleCryptographicProvider(_hybridConfig, _mockLogger.Object);
        }

        [TearDown]
        public void TearDown()
        {
            _provider?.Dispose();
        }

        #region Constructor Tests

        [Test]
        public void Constructor_WithNullConfiguration_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new BouncyCastleCryptographicProvider(null, _mockLogger.Object));
        }

        [Test]
        public void Constructor_WithNullLogger_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new BouncyCastleCryptographicProvider(_hybridConfig, null));
        }

        [Test]
        public void Constructor_WithValidParameters_ShouldInitializeCorrectly()
        {
            // Act
            var provider = new BouncyCastleCryptographicProvider(_hybridConfig, _mockLogger.Object);

            // Assert
            provider.Configuration.Should().Be(_hybridConfig);
        }

        #endregion

        #region Algorithm Support Tests

        [Test]
        [TestCase("ML-KEM-768", true)]
        [TestCase("ML-KEM-1024", true)]
        [TestCase("ML-DSA-65", true)]
        [TestCase("ML-DSA-87", true)]
        [TestCase("RSA-OAEP-2048", true)]
        [TestCase("RSA-OAEP-4096", true)]
        [TestCase("RSA-PSS-2048", true)]
        [TestCase("RSA-PSS-4096", true)]
        [TestCase("AES-256-GCM", true)]
        [TestCase("UNSUPPORTED-ALGO", false)]
        [TestCase("", false)]
        [TestCase(null, false)]
        public void IsAlgorithmSupported_WithVariousAlgorithms_ShouldReturnCorrectSupport(string algorithm, bool expectedSupported)
        {
            // Act
            var isSupported = _provider.IsAlgorithmSupported(algorithm);

            // Assert
            isSupported.Should().Be(expectedSupported);
        }

        #endregion

        #region Key Generation Tests

        [Test]
        public async Task GenerateKeyPairAsync_WithMlKem768_ShouldGenerateValidKeyPair()
        {
            // Act
            var result = await _provider.GenerateKeyPairAsync("ML-KEM-768", false);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();
            result.Data.Algorithm.Should().Be("ML-KEM-768");
            result.Data.IsForSigning.Should().BeFalse();
            result.Data.PublicKey.Should().NotBeNullOrEmpty();
            result.Data.PrivateKey.Should().NotBeNullOrEmpty();
            
            // ML-KEM-768 specific size checks
            result.Data.PublicKey.Length.Should().Be(1184); // ML-KEM-768 public key size
            result.Data.PrivateKey.Length.Should().BeGreaterThan(0);
        }

        [Test]
        public async Task GenerateKeyPairAsync_WithMlDsa65_ShouldGenerateValidSigningKeyPair()
        {
            // Act
            var result = await _provider.GenerateKeyPairAsync("ML-DSA-65", true);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();
            result.Data.Algorithm.Should().Be("ML-DSA-65");
            result.Data.IsForSigning.Should().BeTrue();
            result.Data.PublicKey.Should().NotBeNullOrEmpty();
            result.Data.PrivateKey.Should().NotBeNullOrEmpty();
            
            // ML-DSA-65 specific size checks
            result.Data.PublicKey.Length.Should().BeApproximately(1952, 100); // ML-DSA-65 public key size
            result.Data.PrivateKey.Length.Should().BeGreaterThan(0);
        }

        [Test]
        public async Task GenerateKeyPairAsync_WithRsa2048Signing_ShouldGenerateValidKeyPair()
        {
            // Act
            var result = await _provider.GenerateKeyPairAsync("RSA-PSS-2048", true);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();
            result.Data.Algorithm.Should().Be("RSA-PSS-2048");
            result.Data.IsForSigning.Should().BeTrue();
            result.Data.PublicKey.Should().NotBeNullOrEmpty();
            result.Data.PrivateKey.Should().NotBeNullOrEmpty();
        }

        [Test]
        public async Task GenerateKeyPairAsync_WithRsa4096Encryption_ShouldGenerateValidKeyPair()
        {
            // Act
            var result = await _provider.GenerateKeyPairAsync("RSA-OAEP-4096", false);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();
            result.Data.Algorithm.Should().Be("RSA-OAEP-4096");
            result.Data.IsForSigning.Should().BeFalse();
            result.Data.PublicKey.Should().NotBeNullOrEmpty();
            result.Data.PrivateKey.Should().NotBeNullOrEmpty();
        }

        [Test]
        public async Task GenerateKeyPairAsync_WithUnsupportedAlgorithm_ShouldReturnFailure()
        {
            // Act
            var result = await _provider.GenerateKeyPairAsync("UNSUPPORTED-ALGO", false);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeFalse();
            result.ErrorMessage.Should().Contain("Unsupported algorithm");
        }

        [Test]
        public void GenerateKeyPairAsync_WithNullAlgorithm_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.GenerateKeyPairAsync(null, false));
        }

        [Test]
        public void GenerateKeyPairAsync_WithEmptyAlgorithm_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.GenerateKeyPairAsync("", false));
        }

        #endregion

        #region Encryption/Decryption Tests

        [Test]
        public async Task EncryptAsync_WithValidData_ShouldEncryptSuccessfully()
        {
            // Arrange
            var testData = "Hello, PQC World!"u8.ToArray();
            var keyPair = await _provider.GenerateKeyPairAsync("ML-KEM-768", false);
            
            keyPair.IsSuccess.Should().BeTrue();

            // Act
            var result = await _provider.EncryptAsync(testData, keyPair.Data.PublicKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();
            result.Data.EncryptedData.Should().NotBeNullOrEmpty();
            result.Data.Algorithm.Should().NotBeNullOrEmpty();
            result.Data.Metadata.Should().NotBeNull();
            result.Data.Metadata.IsPostQuantum.Should().BeTrue();
            result.Data.Metadata.IsHybrid.Should().BeTrue();
        }

        [Test]
        public async Task EncryptDecrypt_RoundTrip_ShouldRecoverOriginalData()
        {
            // Arrange
            var testData = "Secret message for PQC encryption test"u8.ToArray();
            var keyPair = await _provider.GenerateKeyPairAsync("ML-KEM-768", false);
            keyPair.IsSuccess.Should().BeTrue();

            // Act - Encrypt
            var encryptResult = await _provider.EncryptAsync(testData, keyPair.Data.PublicKey);
            encryptResult.IsSuccess.Should().BeTrue();

            // Act - Decrypt
            var decryptResult = await _provider.DecryptAsync(encryptResult.Data.EncryptedData, keyPair.Data.PrivateKey);

            // Assert
            decryptResult.Should().NotBeNull();
            decryptResult.IsSuccess.Should().BeTrue();
            decryptResult.Data.Should().NotBeNullOrEmpty();
            decryptResult.Data.Should().BeEquivalentTo(testData);
        }

        [Test]
        public void EncryptAsync_WithNullData_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.EncryptAsync(null, new byte[100]));
        }

        [Test]
        public void EncryptAsync_WithNullPublicKey_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.EncryptAsync(new byte[100], null));
        }

        [Test]
        public void DecryptAsync_WithNullEncryptedData_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.DecryptAsync(null, new byte[100]));
        }

        [Test]
        public void DecryptAsync_WithNullPrivateKey_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.DecryptAsync(new byte[100], null));
        }

        #endregion

        #region Signing/Verification Tests

        [Test]
        public async Task SignAsync_WithValidData_ShouldSignSuccessfully()
        {
            // Arrange
            var testData = "Document to be signed with PQC"u8.ToArray();
            var keyPair = await _provider.GenerateKeyPairAsync("ML-DSA-65", true);
            
            keyPair.IsSuccess.Should().BeTrue();

            // Act
            var result = await _provider.SignAsync(testData, keyPair.Data.PrivateKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();
            result.Data.SignatureData.Should().NotBeNullOrEmpty();
            result.Data.Algorithm.Should().Be("ML-DSA-65");
            result.Data.Metadata.Should().NotBeNull();
            result.Data.Metadata.IsPostQuantum.Should().BeTrue();
            result.Data.Metadata.HashAlgorithm.Should().Be("SHA-256");
            
            // ML-DSA-65 signature size should be approximately 3293 bytes
            result.Data.SignatureData.Length.Should().BeApproximately(3293, 200);
        }

        [Test]
        public async Task SignVerify_RoundTrip_ShouldVerifySignatureSuccessfully()
        {
            // Arrange
            var testData = "Important document requiring digital signature"u8.ToArray();
            var keyPair = await _provider.GenerateKeyPairAsync("ML-DSA-65", true);
            keyPair.IsSuccess.Should().BeTrue();

            // Act - Sign
            var signResult = await _provider.SignAsync(testData, keyPair.Data.PrivateKey);
            signResult.IsSuccess.Should().BeTrue();

            // Act - Verify
            var verifyResult = await _provider.VerifySignatureAsync(testData, signResult.Data.SignatureData, keyPair.Data.PublicKey);

            // Assert
            verifyResult.Should().NotBeNull();
            verifyResult.IsSuccess.Should().BeTrue();
            verifyResult.Data.Should().BeTrue();
        }

        [Test]
        public async Task VerifySignatureAsync_WithTamperedData_ShouldReturnFalse()
        {
            // Arrange
            var originalData = "Original document"u8.ToArray();
            var tamperedData = "Tampered document"u8.ToArray();
            var keyPair = await _provider.GenerateKeyPairAsync("ML-DSA-65", true);
            keyPair.IsSuccess.Should().BeTrue();

            var signResult = await _provider.SignAsync(originalData, keyPair.Data.PrivateKey);
            signResult.IsSuccess.Should().BeTrue();

            // Act - Verify with tampered data
            var verifyResult = await _provider.VerifySignatureAsync(tamperedData, signResult.Data.SignatureData, keyPair.Data.PublicKey);

            // Assert
            verifyResult.Should().NotBeNull();
            verifyResult.IsSuccess.Should().BeTrue();
            verifyResult.Data.Should().BeFalse(); // Signature should not verify
        }

        [Test]
        public void SignAsync_WithNullData_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.SignAsync(null, new byte[100]));
        }

        [Test]
        public void SignAsync_WithNullPrivateKey_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.SignAsync(new byte[100], null));
        }

        [Test]
        public void VerifySignatureAsync_WithNullData_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.VerifySignatureAsync(null, new byte[100], new byte[100]));
        }

        [Test]
        public void VerifySignatureAsync_WithNullSignature_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.VerifySignatureAsync(new byte[100], null, new byte[100]));
        }

        [Test]
        public void VerifySignatureAsync_WithNullPublicKey_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => 
                _provider.VerifySignatureAsync(new byte[100], new byte[100], null));
        }

        #endregion

        #region Performance Metrics Tests

        [Test]
        public async Task GetLastOperationMetrics_AfterOperation_ShouldReturnMetrics()
        {
            // Arrange
            var testData = "Performance test data"u8.ToArray();
            var keyPair = await _provider.GenerateKeyPairAsync("ML-KEM-768", false);
            keyPair.IsSuccess.Should().BeTrue();

            // Act
            await _provider.EncryptAsync(testData, keyPair.Data.PublicKey);
            var metrics = _provider.GetLastOperationMetrics();

            // Assert
            metrics.Should().NotBeNull();
            metrics.Operation.Should().Be("Encrypt");
            metrics.Algorithm.Should().NotBeNullOrEmpty();
            metrics.Duration.Should().BeGreaterThan(TimeSpan.Zero);
            metrics.InputSize.Should().Be(testData.Length);
            metrics.OutputSize.Should().BeGreaterThan(0);
            metrics.Timestamp.Should().BeCloseTo(DateTime.UtcNow, TimeSpan.FromSeconds(5));
        }

        [Test]
        public void GetLastOperationMetrics_BeforeAnyOperation_ShouldReturnNull()
        {
            // Act
            var metrics = _provider.GetLastOperationMetrics();

            // Assert
            metrics.Should().BeNull();
        }

        #endregion

        #region Configuration Mode Tests

        [Test]
        public async Task EncryptAsync_WithPostQuantumOnlyConfig_ShouldUsePqcAlgorithms()
        {
            // Arrange
            var provider = new BouncyCastleCryptographicProvider(_pqcOnlyConfig, _mockLogger.Object);
            var testData = "PQC-only encryption test"u8.ToArray();
            var keyPair = await provider.GenerateKeyPairAsync("ML-KEM-768", false);
            keyPair.IsSuccess.Should().BeTrue();

            // Act
            var result = await provider.EncryptAsync(testData, keyPair.Data.PublicKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Metadata.IsPostQuantum.Should().BeTrue();
            result.Data.Metadata.IsHybrid.Should().BeFalse();
        }

        [Test]
        public async Task EncryptAsync_WithClassicalOnlyConfig_ShouldUseClassicalAlgorithms()
        {
            // Arrange
            var provider = new BouncyCastleCryptographicProvider(_classicalOnlyConfig, _mockLogger.Object);
            var testData = "Classical-only encryption test"u8.ToArray();
            var keyPair = await provider.GenerateKeyPairAsync("RSA-OAEP-2048", false);
            keyPair.IsSuccess.Should().BeTrue();

            // Act
            var result = await provider.EncryptAsync(testData, keyPair.Data.PublicKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Metadata.IsPostQuantum.Should().BeFalse();
            result.Data.Metadata.IsHybrid.Should().BeFalse();
        }

        #endregion

        #region Performance Requirements Tests

        [Test]
        public async Task EncryptAsync_WithLargeData_ShouldCompleteWithinTimeLimit()
        {
            // Arrange
            var largeData = new byte[1024 * 1024]; // 1MB test data
            new Random().NextBytes(largeData);
            
            var keyPair = await _provider.GenerateKeyPairAsync("ML-KEM-768", false);
            keyPair.IsSuccess.Should().BeTrue();

            var startTime = DateTime.UtcNow;

            // Act
            var result = await _provider.EncryptAsync(largeData, keyPair.Data.PublicKey);

            // Assert
            var elapsedTime = DateTime.UtcNow - startTime;
            result.IsSuccess.Should().BeTrue();
            elapsedTime.TotalSeconds.Should().BeLessThan(2.0); // Per requirements: < 2 seconds for typical email
        }

        [Test]
        public async Task SignAsync_WithLargeData_ShouldCompleteWithinTimeLimit()
        {
            // Arrange
            var largeData = new byte[1024 * 1024]; // 1MB test data
            new Random().NextBytes(largeData);
            
            var keyPair = await _provider.GenerateKeyPairAsync("ML-DSA-65", true);
            keyPair.IsSuccess.Should().BeTrue();

            var startTime = DateTime.UtcNow;

            // Act
            var result = await _provider.SignAsync(largeData, keyPair.Data.PrivateKey);

            // Assert
            var elapsedTime = DateTime.UtcNow - startTime;
            result.IsSuccess.Should().BeTrue();
            elapsedTime.TotalSeconds.Should().BeLessThan(2.0);
        }

        #endregion
    }
}