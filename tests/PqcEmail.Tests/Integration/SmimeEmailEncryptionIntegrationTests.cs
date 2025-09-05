using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;
using FluentAssertions;
using PqcEmail.Core.Cryptography;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Integration
{
    /// <summary>
    /// Integration tests for end-to-end S/MIME email encryption scenarios.
    /// These tests validate the complete workflow from message creation to encryption and decryption.
    /// </summary>
    public class SmimeEmailEncryptionIntegrationTests : IDisposable
    {
        private readonly ServiceProvider _serviceProvider;
        private readonly ISmimeMessageProcessor _smimeProcessor;
        private readonly IHybridEncryptionEngine _hybridEngine;
        private readonly ICryptographicProvider _cryptoProvider;
        private readonly IKemRecipientInfoProcessor _kemProcessor;

        public SmimeEmailEncryptionIntegrationTests()
        {
            var services = new ServiceCollection();
            
            // Add logging
            services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Debug));
            
            // Register core services (using mocks for this integration test)
            services.AddSingleton<ICryptographicProvider, MockCryptographicProvider>();
            services.AddSingleton<IHybridEncryptionEngine, HybridEncryptionEngine>();
            services.AddSingleton<IKemRecipientInfoProcessor, KemRecipientInfoProcessor>();
            services.AddSingleton<ISmimeMessageProcessor, SmimeMessageProcessor>();

            _serviceProvider = services.BuildServiceProvider();
            
            _smimeProcessor = _serviceProvider.GetRequiredService<ISmimeMessageProcessor>();
            _hybridEngine = _serviceProvider.GetRequiredService<IHybridEncryptionEngine>();
            _cryptoProvider = _serviceProvider.GetRequiredService<ICryptographicProvider>();
            _kemProcessor = _serviceProvider.GetRequiredService<IKemRecipientInfoProcessor>();
        }

        [Fact]
        public async Task EndToEnd_SingleRecipient_HybridEncryption_ShouldSucceed()
        {
            // Arrange
            var originalMessage = CreateTestEmailMessage(
                from: "alice@company.com",
                to: new[] { "bob@company.com" },
                subject: "Confidential Business Plan",
                body: "This is a confidential message containing sensitive business information."
            );

            var recipient = await CreateTestRecipientAsync("bob@company.com", supportsHybrid: true);
            var recipients = new[] { recipient };

            // Act - Encrypt the message
            var encryptionResult = await _smimeProcessor.EncryptMessageAsync(originalMessage, recipients);

            // Assert - Verify encryption succeeded
            encryptionResult.Should().NotBeNull();
            encryptionResult.IsSuccess.Should().BeTrue();
            
            var encryptedMessage = encryptionResult.Data!;
            encryptedMessage.RecipientInfos.Should().HaveCount(1);
            encryptedMessage.Metadata.Strategy.Should().Be(EncryptionStrategy.Hybrid);
            encryptedMessage.EncryptedData.Should().NotBeEmpty();

            // Act - Decrypt the message
            var recipientKeys = await CreateTestPrivateKeysAsync(supportsHybrid: true);
            var decryptionResult = await _smimeProcessor.DecryptMessageAsync(encryptedMessage, recipientKeys);

            // Assert - Verify decryption succeeded and message is intact
            decryptionResult.Should().NotBeNull();
            decryptionResult.IsSuccess.Should().BeTrue();
            
            var decryptedMessage = decryptionResult.Data!;
            decryptedMessage.From.Should().Be(originalMessage.From);
            decryptedMessage.To.Should().BeEquivalentTo(originalMessage.To);
            decryptedMessage.Subject.Should().Be(originalMessage.Subject);
            decryptedMessage.Body.Should().Be(originalMessage.Body);
        }

        [Fact]
        public async Task EndToEnd_MultipleRecipients_MixedCapabilities_ShouldNegotiateCorrectly()
        {
            // Arrange
            var originalMessage = CreateTestEmailMessage(
                from: "ceo@company.com",
                to: new[] { "alice@company.com", "bob@legacy.com", "charlie@quantum.com" },
                subject: "Strategic Initiative",
                body: "This message is sent to recipients with different cryptographic capabilities."
            );

            var recipients = new[]
            {
                await CreateTestRecipientAsync("alice@company.com", supportsHybrid: true),
                await CreateTestRecipientAsync("bob@legacy.com", supportsHybrid: false), // Classical only
                await CreateTestRecipientAsync("charlie@quantum.com", supportsHybrid: true)
            };

            // Act - Encrypt the message
            var encryptionResult = await _smimeProcessor.EncryptMessageAsync(originalMessage, recipients);

            // Assert - Verify encryption with algorithm negotiation
            encryptionResult.Should().NotBeNull();
            encryptionResult.IsSuccess.Should().BeTrue();
            
            var encryptedMessage = encryptionResult.Data!;
            encryptedMessage.RecipientInfos.Should().HaveCount(3);
            
            // Should fall back to classical due to mixed capabilities
            encryptedMessage.Metadata.Strategy.Should().Be(EncryptionStrategy.ClassicalOnly);
            encryptedMessage.Metadata.AlgorithmNegotiation.AllRecipientsSupported.Should().BeFalse();

            // Act & Assert - Each recipient should be able to decrypt
            await VerifyRecipientCanDecrypt(encryptedMessage, "alice@company.com", supportsHybrid: true);
            await VerifyRecipientCanDecrypt(encryptedMessage, "bob@legacy.com", supportsHybrid: false);
            await VerifyRecipientCanDecrypt(encryptedMessage, "charlie@quantum.com", supportsHybrid: true);
        }

        [Fact]
        public async Task EndToEnd_LargeMessage_WithAttachments_ShouldHandleCorrectly()
        {
            // Arrange
            var attachments = new[]
            {
                new EmailAttachment("document.pdf", "application/pdf", GenerateRandomBytes(50000)),
                new EmailAttachment("image.jpg", "image/jpeg", GenerateRandomBytes(25000)),
                new EmailAttachment("data.xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", GenerateRandomBytes(75000))
            };

            var originalMessage = CreateTestEmailMessage(
                from: "sender@company.com",
                to: new[] { "recipient@company.com" },
                subject: "Large Message with Attachments",
                body: GenerateRandomText(10000), // 10KB body
                attachments: attachments
            );

            var recipient = await CreateTestRecipientAsync("recipient@company.com", supportsHybrid: true);

            // Act - Encrypt large message
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var encryptionResult = await _smimeProcessor.EncryptMessageAsync(originalMessage, new[] { recipient });
            sw.Stop();

            // Assert - Verify performance is acceptable
            sw.ElapsedMilliseconds.Should().BeLessThan(5000); // Should complete within 5 seconds
            
            encryptionResult.Should().NotBeNull();
            encryptionResult.IsSuccess.Should().BeTrue();

            var encryptedMessage = encryptionResult.Data!;
            encryptedMessage.EncryptedData.Should().NotBeEmpty();
            encryptedMessage.EncryptedData.Length.Should().BeGreaterThan(150000); // Should include all content

            // Act - Decrypt large message
            var recipientKeys = await CreateTestPrivateKeysAsync(supportsHybrid: true);
            sw.Restart();
            var decryptionResult = await _smimeProcessor.DecryptMessageAsync(encryptedMessage, recipientKeys);
            sw.Stop();

            // Assert - Verify decryption performance and integrity
            sw.ElapsedMilliseconds.Should().BeLessThan(3000); // Decryption should be faster
            
            decryptionResult.Should().NotBeNull();
            decryptionResult.IsSuccess.Should().BeTrue();
            
            var decryptedMessage = decryptionResult.Data!;
            decryptedMessage.Attachments.Should().HaveCount(3);
            decryptedMessage.Attachments[0].Data.Should().BeEquivalentTo(attachments[0].Data);
            decryptedMessage.Attachments[1].Data.Should().BeEquivalentTo(attachments[1].Data);
            decryptedMessage.Attachments[2].Data.Should().BeEquivalentTo(attachments[2].Data);
        }

        [Fact]
        public async Task EndToEnd_SignAndEncrypt_HybridWorkflow_ShouldSucceed()
        {
            // Arrange
            var originalMessage = CreateTestEmailMessage(
                from: "signer@company.com",
                to: new[] { "recipient@company.com" },
                subject: "Signed and Encrypted Message",
                body: "This message is both digitally signed and encrypted."
            );

            var signingKeys = await CreateTestPrivateKeysAsync(supportsHybrid: true);
            var recipient = await CreateTestRecipientAsync("recipient@company.com", supportsHybrid: true);

            // Act - Sign the message
            var signingResult = await _smimeProcessor.SignMessageAsync(originalMessage, signingKeys);
            signingResult.Should().NotBeNull();
            signingResult.IsSuccess.Should().BeTrue();
            
            var signedMessage = signingResult.Data!;

            // Act - Encrypt the signed message (nested S/MIME)
            var messageToEncrypt = CreateTestEmailMessage(
                from: originalMessage.From,
                to: originalMessage.To.ToArray(),
                subject: originalMessage.Subject,
                body: Convert.ToBase64String(signedMessage.SignedData) // Embed signed data
            );

            var encryptionResult = await _smimeProcessor.EncryptMessageAsync(messageToEncrypt, new[] { recipient });

            // Assert - Verify sign and encrypt succeeded
            encryptionResult.Should().NotBeNull();
            encryptionResult.IsSuccess.Should().BeTrue();
            
            var encryptedMessage = encryptionResult.Data!;
            encryptedMessage.Metadata.Strategy.Should().Be(EncryptionStrategy.Hybrid);

            // Act - Decrypt and verify
            var recipientKeys = await CreateTestPrivateKeysAsync(supportsHybrid: true);
            var decryptionResult = await _smimeProcessor.DecryptMessageAsync(encryptedMessage, recipientKeys);
            
            decryptionResult.Should().NotBeNull();
            decryptionResult.IsSuccess.Should().BeTrue();
            
            var decryptedMessage = decryptionResult.Data!;
            var embeddedSignedData = Convert.FromBase64String(decryptedMessage.Body);

            // Reconstruct signed message for verification
            var reconstructedSignedMessage = new SmimeSignedMessage(
                embeddedSignedData,
                originalMessage,
                signedMessage.Signatures,
                signedMessage.Certificates,
                signedMessage.Metadata
            );

            var senderPublicKeys = await CreateTestPublicKeysAsync();
            var verificationResult = await _smimeProcessor.VerifySignatureAsync(reconstructedSignedMessage, senderPublicKeys);

            // Assert - Verify signature is valid
            verificationResult.Should().NotBeNull();
            verificationResult.IsSuccess.Should().BeTrue();
            verificationResult.Data!.IsValid.Should().BeTrue();
        }

        [Fact]
        public async Task PerformanceTest_100Recipients_ShouldCompleteWithinReasonableTime()
        {
            // Arrange
            var originalMessage = CreateTestEmailMessage(
                from: "broadcast@company.com",
                to: Enumerable.Range(1, 100).Select(i => $"user{i}@company.com").ToArray(),
                subject: "Company-wide Announcement",
                body: "This is a test of bulk encryption to 100 recipients."
            );

            var recipients = new List<SmimeRecipient>();
            for (int i = 1; i <= 100; i++)
            {
                recipients.Add(await CreateTestRecipientAsync($"user{i}@company.com", supportsHybrid: true));
            }

            // Act - Encrypt to 100 recipients
            var sw = System.Diagnostics.Stopwatch.StartNew();
            var encryptionResult = await _smimeProcessor.EncryptMessageAsync(originalMessage, recipients);
            sw.Stop();

            // Assert - Verify performance meets requirements
            sw.ElapsedMilliseconds.Should().BeLessThan(30000); // Should complete within 30 seconds
            
            encryptionResult.Should().NotBeNull();
            encryptionResult.IsSuccess.Should().BeTrue();
            
            var encryptedMessage = encryptionResult.Data!;
            encryptedMessage.RecipientInfos.Should().HaveCount(100);
            encryptedMessage.Metadata.RecipientCount.Should().Be(100);

            // Verify a few random recipients can decrypt
            var testRecipients = new[] { 1, 25, 50, 75, 100 };
            foreach (var recipientNum in testRecipients)
            {
                await VerifyRecipientCanDecrypt(encryptedMessage, $"user{recipientNum}@company.com", supportsHybrid: true);
            }
        }

        [Theory]
        [InlineData(EncryptionStrategy.Hybrid)]
        [InlineData(EncryptionStrategy.PostQuantumOnly)]
        [InlineData(EncryptionStrategy.ClassicalOnly)]
        public async Task EndToEnd_DifferentStrategies_ShouldWorkCorrectly(EncryptionStrategy strategy)
        {
            // Arrange
            var originalMessage = CreateTestEmailMessage(
                from: "sender@test.com",
                to: new[] { "recipient@test.com" },
                subject: $"Test {strategy} Strategy",
                body: $"This message tests the {strategy} encryption strategy."
            );

            bool supportsHybrid = strategy != EncryptionStrategy.ClassicalOnly;
            var recipient = await CreateTestRecipientAsync("recipient@test.com", supportsHybrid);

            // Modify crypto provider configuration to force strategy
            var mockProvider = (MockCryptographicProvider)_cryptoProvider;
            mockProvider.SetMode(strategy switch
            {
                EncryptionStrategy.Hybrid => CryptographicMode.Hybrid,
                EncryptionStrategy.PostQuantumOnly => CryptographicMode.PostQuantumOnly,
                EncryptionStrategy.ClassicalOnly => CryptographicMode.ClassicalOnly,
                _ => CryptographicMode.Hybrid
            });

            // Act
            var encryptionResult = await _smimeProcessor.EncryptMessageAsync(originalMessage, new[] { recipient });

            // Assert
            encryptionResult.Should().NotBeNull();
            encryptionResult.IsSuccess.Should().BeTrue();
            
            var encryptedMessage = encryptionResult.Data!;
            if (strategy == EncryptionStrategy.ClassicalOnly || !supportsHybrid)
            {
                encryptedMessage.Metadata.Strategy.Should().Be(EncryptionStrategy.ClassicalOnly);
            }
            else
            {
                encryptedMessage.Metadata.Strategy.Should().Be(strategy);
            }

            // Verify decryption works
            var recipientKeys = await CreateTestPrivateKeysAsync(supportsHybrid);
            var decryptionResult = await _smimeProcessor.DecryptMessageAsync(encryptedMessage, recipientKeys);
            
            decryptionResult.Should().NotBeNull();
            decryptionResult.IsSuccess.Should().BeTrue();
            decryptionResult.Data!.Subject.Should().Be(originalMessage.Subject);
        }

        #region Helper Methods

        private EmailMessage CreateTestEmailMessage(
            string from,
            string[] to,
            string subject,
            string body,
            IEnumerable<EmailAttachment>? attachments = null)
        {
            return new EmailMessage(
                from: from,
                to: to,
                subject: subject,
                body: body,
                attachments: attachments,
                timestamp: DateTime.UtcNow
            );
        }

        private async Task<SmimeRecipient> CreateTestRecipientAsync(string email, bool supportsHybrid)
        {
            var certificate = CreateTestCertificate(email, supportsHybrid);
            var capabilities = _smimeProcessor.DetermineRecipientCapabilities(new[] { certificate });
            
            return new SmimeRecipient(email, certificate, capabilities);
        }

        private CertificateInfo CreateTestCertificate(string email, bool supportsHybrid)
        {
            var pqcPublicKey = supportsHybrid ? GenerateRandomBytes(1184) : null; // ML-KEM-768
            var classicalPublicKey = GenerateRandomBytes(270); // RSA-2048

            return new CertificateInfo(
                subject: $"CN={email}",
                issuer: "CN=Test CA",
                serialNumber: Convert.ToBase64String(GenerateRandomBytes(8)),
                validFrom: DateTime.UtcNow.AddDays(-30),
                validTo: DateTime.UtcNow.AddDays(365),
                postQuantumEncryptionPublicKey: pqcPublicKey,
                classicalEncryptionPublicKey: classicalPublicKey,
                postQuantumSigningPublicKey: supportsHybrid ? GenerateRandomBytes(1952) : null, // ML-DSA-65
                classicalSigningPublicKey: GenerateRandomBytes(270),
                thumbprint: Convert.ToBase64String(GenerateRandomBytes(20)),
                subjectKeyIdentifier: Convert.ToBase64String(GenerateRandomBytes(20)),
                postQuantumEncryptionAlgorithm: supportsHybrid ? "ML-KEM-768" : null,
                classicalEncryptionAlgorithm: "RSA-2048",
                postQuantumSigningAlgorithm: supportsHybrid ? "ML-DSA-65" : null,
                classicalSigningAlgorithm: "RSA-SHA256"
            );
        }

        private async Task<SmimePrivateKeys> CreateTestPrivateKeysAsync(bool supportsHybrid)
        {
            var pqcEncKey = supportsHybrid ? GenerateRandomBytes(32) : null;
            var classicalEncKey = GenerateRandomBytes(32);
            var pqcSigKey = supportsHybrid ? GenerateRandomBytes(32) : null;
            var classicalSigKey = GenerateRandomBytes(32);

            var algorithms = new SmimeKeyAlgorithms(
                supportsHybrid ? "ML-KEM-768" : null,
                "RSA-2048",
                supportsHybrid ? "ML-DSA-65" : null,
                "RSA-SHA256"
            );

            return new SmimePrivateKeys(pqcEncKey, classicalEncKey, pqcSigKey, classicalSigKey, algorithms);
        }

        private async Task<SmimePublicKeys> CreateTestPublicKeysAsync()
        {
            var algorithms = new SmimeKeyAlgorithms("ML-KEM-768", "RSA-2048", "ML-DSA-65", "RSA-SHA256");
            
            return new SmimePublicKeys(
                GenerateRandomBytes(1184), // ML-KEM-768 public key
                GenerateRandomBytes(270),  // RSA-2048 public key
                GenerateRandomBytes(1952), // ML-DSA-65 public key
                GenerateRandomBytes(270),  // RSA-2048 public key
                algorithms
            );
        }

        private async Task VerifyRecipientCanDecrypt(SmimeEncryptedMessage encryptedMessage, string recipientEmail, bool supportsHybrid)
        {
            var recipientKeys = await CreateTestPrivateKeysAsync(supportsHybrid);
            var decryptionResult = await _smimeProcessor.DecryptMessageAsync(encryptedMessage, recipientKeys);
            
            decryptionResult.Should().NotBeNull();
            decryptionResult.IsSuccess.Should().BeTrue($"Recipient {recipientEmail} should be able to decrypt the message");
        }

        private byte[] GenerateRandomBytes(int size)
        {
            var bytes = new byte[size];
            new Random().NextBytes(bytes);
            return bytes;
        }

        private string GenerateRandomText(int length)
        {
            const string chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 \n\r\t";
            var random = new Random();
            return new string(Enumerable.Repeat(chars, length)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }

        #endregion

        public void Dispose()
        {
            _serviceProvider?.Dispose();
        }
    }

    /// <summary>
    /// Mock implementation of ICryptographicProvider for integration testing.
    /// Simulates PQC and classical cryptographic operations without requiring real crypto libraries.
    /// </summary>
    public class MockCryptographicProvider : ICryptographicProvider
    {
        private AlgorithmConfiguration _configuration;
        private readonly Random _random = new Random();

        public AlgorithmConfiguration Configuration => _configuration;

        public MockCryptographicProvider()
        {
            _configuration = new AlgorithmConfiguration(
                CryptographicMode.Hybrid,
                "ML-KEM-768",
                "ML-DSA-65",
                "RSA-2048",
                "RSA-SHA256"
            );
        }

        public void SetMode(CryptographicMode mode)
        {
            _configuration = new AlgorithmConfiguration(
                mode,
                _configuration.PreferredKemAlgorithm,
                _configuration.PreferredSignatureAlgorithm,
                _configuration.FallbackClassicalAlgorithm,
                _configuration.FallbackClassicalSignatureAlgorithm
            );
        }

        public Task<CryptographicResult<EncryptionResult>> EncryptAsync(byte[] data, byte[] recipientPublicKey)
        {
            // Simulate encryption by returning encrypted data with metadata
            var encryptedData = new byte[data.Length + 16]; // Add some overhead
            _random.NextBytes(encryptedData);
            
            var result = new EncryptionResult(encryptedData, "AES-256-GCM", DateTime.UtcNow);
            return Task.FromResult(CryptographicResult<EncryptionResult>.Success(result));
        }

        public Task<CryptographicResult<byte[]>> DecryptAsync(byte[] encryptedData, byte[] privateKey)
        {
            // Simulate decryption by returning mock decrypted data
            var decryptedData = new byte[Math.Max(1, encryptedData.Length - 16)];
            _random.NextBytes(decryptedData);
            
            return Task.FromResult(CryptographicResult<byte[]>.Success(decryptedData));
        }

        public Task<CryptographicResult<SignatureResult>> SignAsync(byte[] data, byte[] signingPrivateKey)
        {
            // Simulate signing by returning mock signature
            var signature = new byte[64]; // Mock signature size
            _random.NextBytes(signature);
            
            var result = new SignatureResult(signature, "ML-DSA-65", DateTime.UtcNow);
            return Task.FromResult(CryptographicResult<SignatureResult>.Success(result));
        }

        public Task<CryptographicResult<bool>> VerifySignatureAsync(byte[] data, byte[] signature, byte[] signingPublicKey)
        {
            // Simulate verification - always return true for testing
            return Task.FromResult(CryptographicResult<bool>.Success(true));
        }

        public Task<CryptographicResult<KeyPair>> GenerateKeyPairAsync(string algorithmName, bool isForSigning)
        {
            // Generate mock key pair
            var publicKey = new byte[isForSigning ? 1952 : 1184]; // ML-DSA vs ML-KEM sizes
            var privateKey = new byte[32];
            
            _random.NextBytes(publicKey);
            _random.NextBytes(privateKey);
            
            var keyPair = new KeyPair(publicKey, privateKey, algorithmName, isForSigning);
            return Task.FromResult(CryptographicResult<KeyPair>.Success(keyPair));
        }

        public Task<CryptographicResult<KemEncapsulationResult>> KemEncapsulateAsync(byte[] publicKey, string kemAlgorithm)
        {
            // Simulate KEM encapsulation
            var sharedSecret = new byte[32];
            var ciphertext = new byte[1088]; // ML-KEM-768 ciphertext size
            
            _random.NextBytes(sharedSecret);
            _random.NextBytes(ciphertext);
            
            var result = new KemEncapsulationResult(sharedSecret, ciphertext, kemAlgorithm);
            return Task.FromResult(CryptographicResult<KemEncapsulationResult>.Success(result));
        }

        public Task<CryptographicResult<byte[]>> KemDecapsulateAsync(byte[] ciphertext, byte[] privateKey, string kemAlgorithm)
        {
            // Simulate KEM decapsulation by returning mock shared secret
            var sharedSecret = new byte[32];
            _random.NextBytes(sharedSecret);
            
            return Task.FromResult(CryptographicResult<byte[]>.Success(sharedSecret));
        }

        public bool IsAlgorithmSupported(string algorithmName)
        {
            return algorithmName.StartsWith("ML-") || algorithmName.StartsWith("RSA") || algorithmName.StartsWith("ECDSA");
        }

        public PerformanceMetrics? GetLastOperationMetrics()
        {
            return new PerformanceMetrics("mock_operation", "mock_algorithm", TimeSpan.FromMilliseconds(50), 1000, 1000, DateTime.UtcNow);
        }
    }
}