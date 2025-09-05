using System;
using System.Collections.Generic;
using System.Linq;
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
    public class SmimeMessageProcessorTests
    {
        private readonly Mock<IHybridEncryptionEngine> _mockHybridEncryptionEngine;
        private readonly Mock<IKemRecipientInfoProcessor> _mockKemRecipientInfoProcessor;
        private readonly Mock<ICryptographicProvider> _mockCryptographicProvider;
        private readonly Mock<ILogger<SmimeMessageProcessor>> _mockLogger;
        private readonly SmimeMessageProcessor _processor;

        public SmimeMessageProcessorTests()
        {
            _mockHybridEncryptionEngine = new Mock<IHybridEncryptionEngine>();
            _mockKemRecipientInfoProcessor = new Mock<IKemRecipientInfoProcessor>();
            _mockCryptographicProvider = new Mock<ICryptographicProvider>();
            _mockLogger = new Mock<ILogger<SmimeMessageProcessor>>();

            // Setup default cryptographic provider configuration
            var config = new AlgorithmConfiguration(
                CryptographicMode.Hybrid,
                "ML-KEM-768",
                "ML-DSA-65",
                "RSA-2048",
                "RSA-SHA256");
            
            _mockCryptographicProvider.Setup(x => x.Configuration).Returns(config);

            _processor = new SmimeMessageProcessor(
                _mockHybridEncryptionEngine.Object,
                _mockKemRecipientInfoProcessor.Object,
                _mockCryptographicProvider.Object,
                _mockLogger.Object);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithValidInputs_ShouldSucceed()
        {
            // Arrange
            var message = CreateTestEmailMessage();
            var recipients = new[] { CreateTestSmimeRecipient() };

            var kemRecipientInfo = CreateTestKemRecipientInfo();
            _mockKemRecipientInfoProcessor
                .Setup(x => x.CreateKemRecipientInfoAsync(It.IsAny<CertificateInfo>(), It.IsAny<byte[]>(), "ML-KEM-768"))
                .ReturnsAsync(CryptographicResult<KemRecipientInfo>.Success(kemRecipientInfo));

            // Act
            var result = await _processor.EncryptMessageAsync(message, recipients);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();

            var encryptedMessage = result.Data!;
            encryptedMessage.RecipientInfos.Should().HaveCount(1);
            encryptedMessage.ContentEncryptionAlgorithm.Should().Be("AES-256-GCM");
            encryptedMessage.Metadata.RecipientCount.Should().Be(1);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithMultipleRecipients_ShouldCreateMultipleRecipientInfos()
        {
            // Arrange
            var message = CreateTestEmailMessage();
            var recipients = new[]
            {
                CreateTestSmimeRecipient("user1@example.com"),
                CreateTestSmimeRecipient("user2@example.com"),
                CreateTestSmimeRecipient("user3@example.com")
            };

            var kemRecipientInfo = CreateTestKemRecipientInfo();
            _mockKemRecipientInfoProcessor
                .Setup(x => x.CreateKemRecipientInfoAsync(It.IsAny<CertificateInfo>(), It.IsAny<byte[]>(), "ML-KEM-768"))
                .ReturnsAsync(CryptographicResult<KemRecipientInfo>.Success(kemRecipientInfo));

            // Act
            var result = await _processor.EncryptMessageAsync(message, recipients);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data!.RecipientInfos.Should().HaveCount(3);
            result.Data.Metadata.RecipientCount.Should().Be(3);
        }

        [Fact]
        public async Task EncryptMessageAsync_WithNoRecipients_ShouldReturnFailure()
        {
            // Arrange
            var message = CreateTestEmailMessage();
            var recipients = Array.Empty<SmimeRecipient>();

            // Act
            var result = await _processor.EncryptMessageAsync(message, recipients);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeFalse();
            result.ErrorMessage.Should().Contain("No recipients provided");
        }

        [Fact]
        public async Task EncryptMessageAsync_WithNullMessage_ShouldThrowArgumentNullException()
        {
            // Arrange
            var recipients = new[] { CreateTestSmimeRecipient() };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() =>
                _processor.EncryptMessageAsync(null!, recipients));
        }

        [Fact]
        public async Task DecryptMessageAsync_WithValidInputs_ShouldSucceed()
        {
            // Arrange
            var encryptedMessage = CreateTestSmimeEncryptedMessage();
            var privateKeys = CreateTestSmimePrivateKeys();

            var contentEncryptionKey = new byte[32];
            new Random().NextBytes(contentEncryptionKey);

            _mockKemRecipientInfoProcessor
                .Setup(x => x.ProcessKemRecipientInfoAsync(It.IsAny<KemRecipientInfo>(), It.IsAny<byte[]>()))
                .ReturnsAsync(CryptographicResult<byte[]>.Success(contentEncryptionKey));

            // Act
            var result = await _processor.DecryptMessageAsync(encryptedMessage, privateKeys);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();

            var decryptedMessage = result.Data!;
            decryptedMessage.From.Should().NotBeEmpty();
            decryptedMessage.Subject.Should().NotBeEmpty();
        }

        [Fact]
        public async Task DecryptMessageAsync_WithNoMatchingPrivateKey_ShouldReturnFailure()
        {
            // Arrange
            var encryptedMessage = CreateTestSmimeEncryptedMessage();
            var privateKeys = CreateTestSmimePrivateKeys(includePqc: false, includeClassical: false);

            // Act
            var result = await _processor.DecryptMessageAsync(encryptedMessage, privateKeys);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeFalse();
            result.ErrorMessage.Should().Contain("Failed to decrypt content encryption key");
        }

        [Fact]
        public async Task SignMessageAsync_WithValidInputs_ShouldSucceed()
        {
            // Arrange
            var message = CreateTestEmailMessage();
            var signingKeys = CreateTestSmimePrivateKeys();

            var pqSignatureResult = new SignatureResult(
                new byte[] { 0xAA, 0xBB, 0xCC },
                "ML-DSA-65",
                DateTime.UtcNow);

            var classicalSignatureResult = new SignatureResult(
                new byte[] { 0xDD, 0xEE, 0xFF },
                "RSA-SHA256",
                DateTime.UtcNow);

            _mockCryptographicProvider
                .Setup(x => x.SignAsync(It.IsAny<byte[]>(), signingKeys.PostQuantumSigningKey!))
                .ReturnsAsync(CryptographicResult<SignatureResult>.Success(pqSignatureResult));

            _mockCryptographicProvider
                .Setup(x => x.SignAsync(It.IsAny<byte[]>(), signingKeys.ClassicalSigningKey!))
                .ReturnsAsync(CryptographicResult<SignatureResult>.Success(classicalSignatureResult));

            // Act
            var result = await _processor.SignMessageAsync(message, signingKeys);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();

            var signedMessage = result.Data!;
            signedMessage.Signatures.Should().HaveCount(2); // Both PQC and classical signatures
            signedMessage.OriginalMessage.Should().Be(message);
        }

        [Fact]
        public async Task SignMessageAsync_WithOnlyPqcSigningKey_ShouldCreateOnePqcSignature()
        {
            // Arrange
            var message = CreateTestEmailMessage();
            var signingKeys = CreateTestSmimePrivateKeys(includeClassical: false);

            var pqSignatureResult = new SignatureResult(
                new byte[] { 0xAA, 0xBB, 0xCC },
                "ML-DSA-65",
                DateTime.UtcNow);

            _mockCryptographicProvider
                .Setup(x => x.SignAsync(It.IsAny<byte[]>(), signingKeys.PostQuantumSigningKey!))
                .ReturnsAsync(CryptographicResult<SignatureResult>.Success(pqSignatureResult));

            // Act
            var result = await _processor.SignMessageAsync(message, signingKeys);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data!.Signatures.Should().HaveCount(1);
            result.Data.Metadata.Strategy.Should().Be(EncryptionStrategy.PostQuantumOnly);
        }

        [Fact]
        public async Task VerifySignatureAsync_WithValidSignature_ShouldReturnValid()
        {
            // Arrange
            var signedMessage = CreateTestSmimeSignedMessage();
            var senderPublicKeys = CreateTestSmimePublicKeys();

            _mockCryptographicProvider
                .Setup(x => x.VerifySignatureAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(CryptographicResult<bool>.Success(true));

            // Act
            var result = await _processor.VerifySignatureAsync(signedMessage, senderPublicKeys);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data.Should().NotBeNull();
            result.Data!.IsValid.Should().BeTrue();
        }

        [Fact]
        public async Task VerifySignatureAsync_WithInvalidSignature_ShouldReturnInvalid()
        {
            // Arrange
            var signedMessage = CreateTestSmimeSignedMessage();
            var senderPublicKeys = CreateTestSmimePublicKeys();

            _mockCryptographicProvider
                .Setup(x => x.VerifySignatureAsync(It.IsAny<byte[]>(), It.IsAny<byte[]>(), It.IsAny<byte[]>()))
                .ReturnsAsync(CryptographicResult<bool>.Success(false));

            // Act
            var result = await _processor.VerifySignatureAsync(signedMessage, senderPublicKeys);

            // Assert
            result.Should().NotBeNull();
            result.IsSuccess.Should().BeTrue();
            result.Data!.IsValid.Should().BeFalse();
        }

        [Theory]
        [InlineData(true, true, true)] // Hybrid capability
        [InlineData(true, false, false)] // PQC only
        [InlineData(false, true, false)] // Classical only
        [InlineData(false, false, false)] // No capabilities
        public void DetermineRecipientCapabilities_WithVariousCapabilities_ShouldReturnCorrectResult(
            bool hasPqcKey, bool hasClassicalKey, bool expectedHybrid)
        {
            // Arrange
            var certificates = new[] { CreateTestCertificateInfo(hasPqcKey, hasClassicalKey) };

            // Act
            var capabilities = _processor.DetermineRecipientCapabilities(certificates);

            // Assert
            capabilities.Should().NotBeNull();
            capabilities.SupportsPostQuantum.Should().Be(hasPqcKey);
            capabilities.SupportsHybrid.Should().Be(expectedHybrid);
            
            if (hasPqcKey)
            {
                capabilities.SupportedPqcKemAlgorithms.Should().Contain("ML-KEM-768");
            }
            
            if (hasClassicalKey)
            {
                capabilities.SupportedClassicalAlgorithms.Should().Contain("RSA-2048");
            }
        }

        [Fact]
        public void NegotiateEncryptionAlgorithms_WithHybridCapableRecipients_ShouldSelectHybrid()
        {
            // Arrange
            var recipients = new[]
            {
                CreateTestSmimeRecipient("user1@example.com", supportsHybrid: true),
                CreateTestSmimeRecipient("user2@example.com", supportsHybrid: true)
            };

            // Act
            var negotiation = _processor.NegotiateEncryptionAlgorithms(recipients);

            // Assert
            negotiation.Should().NotBeNull();
            negotiation.NegotiatedStrategy.Should().Be(EncryptionStrategy.Hybrid);
            negotiation.AllRecipientsSupported.Should().BeTrue();
            negotiation.RecipientKemAlgorithms.Should().HaveCount(2);
        }

        [Fact]
        public void NegotiateEncryptionAlgorithms_WithMixedCapabilities_ShouldFallbackToClassical()
        {
            // Arrange
            var recipients = new[]
            {
                CreateTestSmimeRecipient("user1@example.com", supportsHybrid: true),
                CreateTestSmimeRecipient("user2@example.com", supportsHybrid: false) // Only classical
            };

            // Act
            var negotiation = _processor.NegotiateEncryptionAlgorithms(recipients);

            // Assert
            negotiation.Should().NotBeNull();
            negotiation.NegotiatedStrategy.Should().Be(EncryptionStrategy.ClassicalOnly);
            negotiation.AllRecipientsSupported.Should().BeFalse();
            negotiation.UnsupportedCapabilities.Should().NotBeEmpty();
        }

        [Fact]
        public void NegotiateEncryptionAlgorithms_WithNoRecipients_ShouldThrowArgumentException()
        {
            // Arrange
            var recipients = Array.Empty<SmimeRecipient>();

            // Act & Assert
            Assert.Throws<ArgumentException>(() => _processor.NegotiateEncryptionAlgorithms(recipients));
        }

        #region Test Helper Methods

        private EmailMessage CreateTestEmailMessage()
        {
            return new EmailMessage(
                from: "sender@example.com",
                to: new[] { "recipient@example.com" },
                cc: new[] { "cc@example.com" },
                subject: "Test Subject",
                body: "This is a test message body with some content.",
                contentType: "text/plain",
                timestamp: DateTime.UtcNow
            );
        }

        private SmimeRecipient CreateTestSmimeRecipient(string email = "recipient@example.com", bool supportsHybrid = true)
        {
            var certificate = CreateTestCertificateInfo(true, true);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: supportsHybrid,
                supportedPqcKemAlgorithms: supportsHybrid ? new[] { "ML-KEM-768" } : Array.Empty<string>(),
                supportedPqcSignatureAlgorithms: supportsHybrid ? new[] { "ML-DSA-65" } : Array.Empty<string>(),
                supportedClassicalAlgorithms: new[] { "RSA-2048", "ECDSA-P256" },
                supportsHybrid: supportsHybrid
            );

            return new SmimeRecipient(email, certificate, capabilities);
        }

        private CertificateInfo CreateTestCertificateInfo(bool includePqcKey = true, bool includeClassicalKey = true)
        {
            var pqcPublicKey = includePqcKey ? new byte[1184] : null; // ML-KEM-768 public key size
            var classicalPublicKey = includeClassicalKey ? new byte[270] : null; // RSA-2048 public key size

            if (pqcPublicKey != null) new Random().NextBytes(pqcPublicKey);
            if (classicalPublicKey != null) new Random().NextBytes(classicalPublicKey);

            return new CertificateInfo(
                subject: "CN=Test User",
                issuer: "CN=Test CA",
                serialNumber: Convert.ToBase64String(new byte[] { 0x01, 0x02, 0x03 }),
                validFrom: DateTime.UtcNow.AddDays(-30),
                validTo: DateTime.UtcNow.AddDays(365),
                postQuantumEncryptionPublicKey: pqcPublicKey,
                classicalEncryptionPublicKey: classicalPublicKey,
                postQuantumSigningPublicKey: null,
                classicalSigningPublicKey: null,
                thumbprint: Convert.ToBase64String(new byte[] { 0xAA, 0xBB }),
                subjectKeyIdentifier: Convert.ToBase64String(new byte[] { 0x11, 0x22 }),
                postQuantumEncryptionAlgorithm: includePqcKey ? "ML-KEM-768" : null,
                classicalEncryptionAlgorithm: includeClassicalKey ? "RSA-2048" : null,
                postQuantumSigningAlgorithm: null,
                classicalSigningAlgorithm: null
            );
        }

        private SmimePrivateKeys CreateTestSmimePrivateKeys(bool includePqc = true, bool includeClassical = true)
        {
            var pqcEncryptionKey = includePqc ? new byte[32] : null;
            var classicalEncryptionKey = includeClassical ? new byte[32] : null;
            var pqcSigningKey = includePqc ? new byte[32] : null;
            var classicalSigningKey = includeClassical ? new byte[32] : null;

            if (pqcEncryptionKey != null) new Random().NextBytes(pqcEncryptionKey);
            if (classicalEncryptionKey != null) new Random().NextBytes(classicalEncryptionKey);
            if (pqcSigningKey != null) new Random().NextBytes(pqcSigningKey);
            if (classicalSigningKey != null) new Random().NextBytes(classicalSigningKey);

            var algorithms = new SmimeKeyAlgorithms(
                includePqc ? "ML-KEM-768" : null,
                includeClassical ? "RSA-2048" : null,
                includePqc ? "ML-DSA-65" : null,
                includeClassical ? "RSA-SHA256" : null
            );

            return new SmimePrivateKeys(
                pqcEncryptionKey, classicalEncryptionKey, 
                pqcSigningKey, classicalSigningKey, 
                algorithms);
        }

        private SmimePublicKeys CreateTestSmimePublicKeys()
        {
            var pqcEncryptionKey = new byte[1184]; // ML-KEM-768 public key size
            var classicalEncryptionKey = new byte[270]; // RSA-2048 public key size
            var pqcSigningKey = new byte[1952]; // ML-DSA-65 public key size
            var classicalSigningKey = new byte[270]; // RSA-2048 public key size

            new Random().NextBytes(pqcEncryptionKey);
            new Random().NextBytes(classicalEncryptionKey);
            new Random().NextBytes(pqcSigningKey);
            new Random().NextBytes(classicalSigningKey);

            var algorithms = new SmimeKeyAlgorithms("ML-KEM-768", "RSA-2048", "ML-DSA-65", "RSA-SHA256");

            return new SmimePublicKeys(
                pqcEncryptionKey, classicalEncryptionKey,
                pqcSigningKey, classicalSigningKey,
                algorithms);
        }

        private KemRecipientInfo CreateTestKemRecipientInfo()
        {
            var recipientId = new RecipientIdentifier(new byte[] { 0x11, 0x22, 0x33 });
            var kemAlgorithm = new AlgorithmIdentifier(AlgorithmOids.MlKem768);
            var encapsulatedKey = new byte[1088]; // ML-KEM-768 ciphertext size
            var kdfAlgorithm = new AlgorithmIdentifier(AlgorithmOids.Hkdf);
            var keyEncryptionAlgorithm = new AlgorithmIdentifier(AlgorithmOids.Aes256Gcm);
            var encryptedKey = new byte[48]; // 32 bytes CEK + 12 IV + 16 auth tag for AES-GCM

            new Random().NextBytes(encapsulatedKey);
            new Random().NextBytes(encryptedKey);

            return new KemRecipientInfo(
                recipientId, kemAlgorithm, encapsulatedKey,
                kdfAlgorithm, keyEncryptionAlgorithm, encryptedKey, 256);
        }

        private SmimeEncryptedMessage CreateTestSmimeEncryptedMessage()
        {
            var encryptedData = new byte[1000];
            new Random().NextBytes(encryptedData);

            var kemRecipientInfo = CreateTestKemRecipientInfo();
            var recipientInfos = new RecipientInfo[] { new KemRecipientInfoWrapper(kemRecipientInfo) };

            var negotiation = new SmimeAlgorithmNegotiation(
                EncryptionStrategy.Hybrid,
                "AES-256-GCM",
                new Dictionary<string, string> { ["recipient@example.com"] = "ML-KEM-768" },
                true);

            var metadata = new SmimeEncryptionMetadata(
                DateTime.UtcNow,
                EncryptionStrategy.Hybrid,
                negotiation,
                1);

            return new SmimeEncryptedMessage(
                encryptedData,
                recipientInfos,
                "AES-256-GCM",
                metadata);
        }

        private SmimeSignedMessage CreateTestSmimeSignedMessage()
        {
            var signedData = new byte[1500];
            new Random().NextBytes(signedData);

            var message = CreateTestEmailMessage();
            
            var signatures = new[]
            {
                new SignatureInfo(
                    new AlgorithmIdentifier(AlgorithmOids.MlDsa65),
                    new byte[] { 0xAA, 0xBB, 0xCC },
                    new RecipientIdentifier(new byte[] { 0x11, 0x22, 0x33 }))
            };

            var certificates = new[] { CreateTestCertificateInfo() };

            var algorithms = new SmimeKeyAlgorithms("ML-KEM-768", "RSA-2048", "ML-DSA-65", "RSA-SHA256");
            var metadata = new SmimeSigningMetadata(
                DateTime.UtcNow,
                EncryptionStrategy.Hybrid,
                algorithms);

            return new SmimeSignedMessage(signedData, message, signatures, certificates, metadata);
        }

        #endregion
    }
}