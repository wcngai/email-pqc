using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using FluentAssertions;
using PqcEmail.Core.Cryptography;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Cryptography
{
    public class KemRecipientInfoProcessorTests
    {
        private readonly Mock<ICryptographicProvider> _mockCryptographicProvider;
        private readonly Mock<ILogger<KemRecipientInfoProcessor>> _mockLogger;
        private readonly KemRecipientInfoProcessor _processor;

        public KemRecipientInfoProcessorTests()
        {
            _mockCryptographicProvider = new Mock<ICryptographicProvider>();
            _mockLogger = new Mock<ILogger<KemRecipientInfoProcessor>>();
            _processor = new KemRecipientInfoProcessor(_mockCryptographicProvider.Object, _mockLogger.Object);
        }

        [Fact]
        public async Task CreateKemRecipientInfoAsync_WithValidInputs_ShouldSucceed()
        {
            // Arrange
            var certificate = CreateTestCertificate();
            var keyEncapsulationKey = new byte[32];
            new Random().NextBytes(keyEncapsulationKey);
            var kemAlgorithm = "ML-KEM-768";

            var sharedSecret = new byte[32];
            var ciphertext = new byte[1088]; // ML-KEM-768 ciphertext size
            new Random().NextBytes(sharedSecret);
            new Random().NextBytes(ciphertext);

            var kemEncapsulationResult = new KemEncapsulationResult(sharedSecret, ciphertext, kemAlgorithm);
            _mockCryptographicProvider
                .Setup(x => x.KemEncapsulateAsync(It.IsAny<byte[]>(), kemAlgorithm))
                .ReturnsAsync(CryptographicResult<KemEncapsulationResult>.Success(kemEncapsulationResult));

            // Act
            var result = await _processor.CreateKemRecipientInfoAsync(certificate, keyEncapsulationKey, kemAlgorithm);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();

            var kemRecipientInfo = result.Data!;
            kemRecipientInfo.KemAlgorithm.Algorithm.Should().Be(AlgorithmOids.MlKem768);
            kemRecipientInfo.EncapsulatedKey.Should().BeEquivalentTo(ciphertext);
            kemRecipientInfo.KeySize.Should().Be(256); // 32 bytes * 8 bits
        }

        [Fact]
        public async Task CreateKemRecipientInfoAsync_WithNullCertificate_ShouldThrowArgumentNullException()
        {
            // Arrange
            var keyEncapsulationKey = new byte[32];
            var kemAlgorithm = "ML-KEM-768";

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _processor.CreateKemRecipientInfoAsync(null!, keyEncapsulationKey, kemAlgorithm));
        }

        [Fact]
        public async Task CreateKemRecipientInfoAsync_WithKemEncapsulationFailure_ShouldReturnFailure()
        {
            // Arrange
            var certificate = CreateTestCertificate();
            var keyEncapsulationKey = new byte[32];
            var kemAlgorithm = "ML-KEM-768";

            _mockCryptographicProvider
                .Setup(x => x.KemEncapsulateAsync(It.IsAny<byte[]>(), kemAlgorithm))
                .ReturnsAsync(CryptographicResult<KemEncapsulationResult>.Failure("KEM encapsulation failed"));

            // Act
            var result = await _processor.CreateKemRecipientInfoAsync(certificate, keyEncapsulationKey, kemAlgorithm);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeFalse();
            result.ErrorMessage.Should().Contain("KEM encapsulation failed");
        }

        [Fact]
        public async Task ProcessKemRecipientInfoAsync_WithValidInputs_ShouldSucceed()
        {
            // Arrange
            var kemRecipientInfo = CreateTestKemRecipientInfo();
            var privateKey = new byte[32];
            new Random().NextBytes(privateKey);

            var expectedKey = new byte[32];
            new Random().NextBytes(expectedKey);

            _mockCryptographicProvider
                .Setup(x => x.KemDecapsulateAsync(kemRecipientInfo.EncapsulatedKey, privateKey, "ML-KEM-768"))
                .ReturnsAsync(CryptographicResult<byte[]>.Success(expectedKey));

            // Act
            var result = await _processor.ProcessKemRecipientInfoAsync(kemRecipientInfo, privateKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();
            result.Data.Should().HaveCount(32); // Should recover the original CEK
        }

        [Fact]
        public async Task ProcessKemRecipientInfoAsync_WithNullKemRecipientInfo_ShouldThrowArgumentNullException()
        {
            // Arrange
            var privateKey = new byte[32];

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _processor.ProcessKemRecipientInfoAsync(null!, privateKey));
        }

        [Fact]
        public async Task ProcessKemRecipientInfoAsync_WithDecapsulationFailure_ShouldReturnFailure()
        {
            // Arrange
            var kemRecipientInfo = CreateTestKemRecipientInfo();
            var privateKey = new byte[32];

            _mockCryptographicProvider
                .Setup(x => x.KemDecapsulateAsync(It.IsAny<byte[]>(), privateKey, It.IsAny<string>()))
                .ReturnsAsync(CryptographicResult<byte[]>.Failure("KEM decapsulation failed"));

            // Act
            var result = await _processor.ProcessKemRecipientInfoAsync(kemRecipientInfo, privateKey);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeFalse();
            result.ErrorMessage.Should().Contain("KEM decapsulation failed");
        }

        [Theory]
        [InlineData("ML-KEM-512", AlgorithmOids.MlKem512)]
        [InlineData("ML-KEM-768", AlgorithmOids.MlKem768)]
        [InlineData("ML-KEM-1024", AlgorithmOids.MlKem1024)]
        public async Task CreateKemRecipientInfoAsync_WithDifferentAlgorithms_ShouldUseCorrectOid(
            string algorithm, string expectedOid)
        {
            // Arrange
            var certificate = CreateTestCertificate();
            var keyEncapsulationKey = new byte[32];
            var sharedSecret = new byte[32];
            var ciphertext = new byte[1088];
            new Random().NextBytes(sharedSecret);
            new Random().NextBytes(ciphertext);

            var kemEncapsulationResult = new KemEncapsulationResult(sharedSecret, ciphertext, algorithm);
            _mockCryptographicProvider
                .Setup(x => x.KemEncapsulateAsync(It.IsAny<byte[]>(), algorithm))
                .ReturnsAsync(CryptographicResult<KemEncapsulationResult>.Success(kemEncapsulationResult));

            // Act
            var result = await _processor.CreateKemRecipientInfoAsync(certificate, keyEncapsulationKey, algorithm);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data!.KemAlgorithm.Algorithm.Should().Be(expectedOid);
        }

        [Fact]
        public void EncodeKemRecipientInfo_WithValidInput_ShouldProduceValidAsn1()
        {
            // Arrange
            var kemRecipientInfo = CreateTestKemRecipientInfo();

            // Act
            var encoded = _processor.EncodeKemRecipientInfo(kemRecipientInfo);

            // Assert
            encoded.Should().NotBeNull();
            encoded.Should().NotBeEmpty();
            encoded[0].Should().Be(0x30); // Should start with SEQUENCE tag
        }

        [Fact]
        public void DecodeKemRecipientInfo_WithValidAsn1_ShouldRecreateOriginal()
        {
            // Arrange
            var originalKemRecipientInfo = CreateTestKemRecipientInfo();
            var encoded = _processor.EncodeKemRecipientInfo(originalKemRecipientInfo);

            // Act
            var decoded = _processor.DecodeKemRecipientInfo(encoded);

            // Assert
            decoded.Should().NotBeNull();
            decoded.KemAlgorithm.Algorithm.Should().Be(originalKemRecipientInfo.KemAlgorithm.Algorithm);
            decoded.EncapsulatedKey.Should().BeEquivalentTo(originalKemRecipientInfo.EncapsulatedKey);
            decoded.EncryptedKey.Should().BeEquivalentTo(originalKemRecipientInfo.EncryptedKey);
            decoded.KeySize.Should().Be(originalKemRecipientInfo.KeySize);
        }

        [Fact]
        public void EncodeKemRecipientInfo_WithNullInput_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => _processor.EncodeKemRecipientInfo(null!));
        }

        [Fact]
        public void DecodeKemRecipientInfo_WithInvalidAsn1_ShouldThrowArgumentException()
        {
            // Arrange
            var invalidAsn1 = new byte[] { 0xFF, 0xFF, 0xFF }; // Invalid ASN.1 data

            // Act & Assert
            Assert.Throws<ArgumentException>(() => _processor.DecodeKemRecipientInfo(invalidAsn1));
        }

        [Fact]
        public void DecodeKemRecipientInfo_WithEmptyInput_ShouldThrowArgumentException()
        {
            // Arrange
            var emptyAsn1 = new byte[0];

            // Act & Assert
            Assert.Throws<ArgumentException>(() => _processor.DecodeKemRecipientInfo(emptyAsn1));
        }

        [Fact]
        public async Task CreateKemRecipientInfoAsync_WithCertificateWithoutPqcKey_ShouldReturnFailure()
        {
            // Arrange
            var certificate = CreateTestCertificate(includePqcKey: false);
            var keyEncapsulationKey = new byte[32];
            var kemAlgorithm = "ML-KEM-768";

            // Act
            var result = await _processor.CreateKemRecipientInfoAsync(certificate, keyEncapsulationKey, kemAlgorithm);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeFalse();
            result.ErrorMessage.Should().Contain("does not contain a compatible PQC public key");
        }

        [Theory]
        [InlineData("")]
        [InlineData(" ")]
        [InlineData(null)]
        public async Task CreateKemRecipientInfoAsync_WithInvalidAlgorithm_ShouldThrowArgumentException(string algorithm)
        {
            // Arrange
            var certificate = CreateTestCertificate();
            var keyEncapsulationKey = new byte[32];

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() =>
                _processor.CreateKemRecipientInfoAsync(certificate, keyEncapsulationKey, algorithm));
        }

        #region Test Helper Methods

        private CertificateInfo CreateTestCertificate(bool includePqcKey = true)
        {
            var pqcPublicKey = includePqcKey ? new byte[1184] : null; // ML-KEM-768 public key size
            if (pqcPublicKey != null)
            {
                new Random().NextBytes(pqcPublicKey);
            }

            var classicalPublicKey = new byte[270]; // Typical RSA-2048 public key size
            new Random().NextBytes(classicalPublicKey);

            return new CertificateInfo(
                subject: "CN=Test User, O=Test Org",
                issuer: "CN=Test CA, O=Test Org",
                serialNumber: Convert.ToBase64String(new byte[] { 0x01, 0x02, 0x03 }),
                validFrom: DateTime.UtcNow.AddDays(-30),
                validTo: DateTime.UtcNow.AddDays(365),
                postQuantumEncryptionPublicKey: pqcPublicKey,
                classicalEncryptionPublicKey: classicalPublicKey,
                postQuantumSigningPublicKey: null,
                classicalSigningPublicKey: null,
                thumbprint: Convert.ToBase64String(new byte[] { 0xAA, 0xBB, 0xCC }),
                subjectKeyIdentifier: Convert.ToBase64String(new byte[] { 0x11, 0x22, 0x33 }),
                postQuantumEncryptionAlgorithm: includePqcKey ? "ML-KEM-768" : null,
                classicalEncryptionAlgorithm: "RSA-2048",
                postQuantumSigningAlgorithm: null,
                classicalSigningAlgorithm: null
            );
        }

        private KemRecipientInfo CreateTestKemRecipientInfo()
        {
            var recipientId = new RecipientIdentifier(new byte[] { 0x11, 0x22, 0x33 });
            var kemAlgorithm = new AlgorithmIdentifier(AlgorithmOids.MlKem768);
            var encapsulatedKey = new byte[1088]; // ML-KEM-768 ciphertext size
            var kdfAlgorithm = new AlgorithmIdentifier(AlgorithmOids.Hkdf);
            var keyEncryptionAlgorithm = new AlgorithmIdentifier(AlgorithmOids.Aes256Gcm);
            var encryptedKey = new byte[48]; // 32 bytes CEK + 12 IV + 16 auth tag for AES-GCM
            var keySize = 256; // bits

            new Random().NextBytes(encapsulatedKey);
            new Random().NextBytes(encryptedKey);

            return new KemRecipientInfo(
                recipientId,
                kemAlgorithm,
                encapsulatedKey,
                kdfAlgorithm,
                keyEncryptionAlgorithm,
                encryptedKey,
                keySize
            );
        }

        #endregion
    }
}