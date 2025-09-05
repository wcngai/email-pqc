using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using NUnit.Framework;
using FluentAssertions;
using PqcEmail.Core.Cryptography;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Integration
{
    [TestFixture]
    public class CryptographicIntegrationTests
    {
        private ICryptographicProvider _provider;
        private IHybridEncryptionEngine _hybridEngine;
        private AlgorithmSelector _algorithmSelector;
        private ILogger<BouncyCastleCryptographicProvider> _providerLogger;
        private ILogger<HybridEncryptionEngine> _engineLogger;
        private ILogger<AlgorithmSelector> _selectorLogger;

        [OneTimeSetUp]
        public void OneTimeSetUp()
        {
            // Create loggers
            var loggerFactory = LoggerFactory.Create(builder => builder.AddConsole());
            _providerLogger = loggerFactory.CreateLogger<BouncyCastleCryptographicProvider>();
            _engineLogger = loggerFactory.CreateLogger<HybridEncryptionEngine>();
            _selectorLogger = loggerFactory.CreateLogger<AlgorithmSelector>();

            // Create configuration
            var config = AlgorithmConfiguration.CreateDefault();

            // Initialize components
            _provider = new BouncyCastleCryptographicProvider(config, _providerLogger);
            _hybridEngine = new HybridEncryptionEngine(_provider, _engineLogger);
            _algorithmSelector = new AlgorithmSelector(config, _provider, _selectorLogger);
        }

        [OneTimeTearDown]
        public void OneTimeTearDown()
        {
            (_provider as IDisposable)?.Dispose();
        }

        #region Full Workflow Integration Tests

        [Test]
        public async Task FullWorkflow_HybridEncryption_ShouldWorkEndToEnd()
        {
            // Arrange - Simulate email content
            var emailContent = @"
Subject: Quarterly Financial Report - Confidential
From: cfo@financialcorp.com
To: board@financialcorp.com

Dear Board Members,

Please find attached the Q3 financial results. This information is highly confidential
and contains sensitive financial data including:
- Revenue figures: $150.2M
- Profit margins: 23.4%
- Customer acquisition costs
- Strategic partnership details

This email demonstrates post-quantum cryptography protection for financial communications.

Best regards,
Chief Financial Officer
Financial Corp Inc.
            ".Trim();

            var emailBytes = System.Text.Encoding.UTF8.GetBytes(emailContent);

            // Generate key pairs for both sender and recipient
            var senderPqcEncKeyPair = await _provider.GenerateKeyPairAsync("ML-KEM-768", false);
            var senderPqcSigKeyPair = await _provider.GenerateKeyPairAsync("ML-DSA-65", true);
            var senderClassicalEncKeyPair = await _provider.GenerateKeyPairAsync("RSA-OAEP-2048", false);
            var senderClassicalSigKeyPair = await _provider.GenerateKeyPairAsync("RSA-PSS-2048", true);

            var recipientPqcEncKeyPair = await _provider.GenerateKeyPairAsync("ML-KEM-768", false);
            var recipientClassicalEncKeyPair = await _provider.GenerateKeyPairAsync("RSA-OAEP-2048", false);

            // Verify all key generation succeeded
            senderPqcEncKeyPair.IsSuccess.Should().BeTrue();
            senderPqcSigKeyPair.IsSuccess.Should().BeTrue();
            senderClassicalEncKeyPair.IsSuccess.Should().BeTrue();
            senderClassicalSigKeyPair.IsSuccess.Should().BeTrue();
            recipientPqcEncKeyPair.IsSuccess.Should().BeTrue();
            recipientClassicalEncKeyPair.IsSuccess.Should().BeTrue();

            // Step 1: Algorithm Selection
            var recipientCapabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048", "RSA-PSS-2048" },
                supportsHybrid: true
            );

            var strategyRecommendation = _algorithmSelector.RecommendEncryptionStrategy(recipientCapabilities);
            var kemSelection = _algorithmSelector.SelectKemAlgorithm(recipientCapabilities);
            var sigSelection = _algorithmSelector.SelectSignatureAlgorithm(recipientCapabilities);

            // Verify intelligent algorithm selection
            strategyRecommendation.Strategy.Should().Be(EncryptionStrategy.Hybrid);
            strategyRecommendation.ConfidenceScore.Should().BeGreaterThan(0.8f);
            kemSelection.IsHybrid.Should().BeTrue();
            sigSelection.IsHybrid.Should().BeTrue();

            // Step 2: Digital Signature Creation
            var signatureResult = await _provider.SignAsync(emailBytes, senderPqcSigKeyPair.Data.PrivateKey);
            signatureResult.IsSuccess.Should().BeTrue();
            signatureResult.Data.Algorithm.Should().Be("ML-DSA-65");
            signatureResult.Data.Metadata.IsPostQuantum.Should().BeTrue();

            // Step 3: Hybrid Encryption
            var encryptionStartTime = DateTime.UtcNow;
            var hybridEncryptionResult = await _hybridEngine.EncryptHybridAsync(
                emailBytes,
                recipientPqcEncKeyPair.Data.PublicKey,
                recipientClassicalEncKeyPair.Data.PublicKey
            );
            var encryptionDuration = DateTime.UtcNow - encryptionStartTime;

            // Verify encryption success and performance
            hybridEncryptionResult.IsSuccess.Should().BeTrue();
            hybridEncryptionResult.Data.Strategy.Should().Be(EncryptionStrategy.Hybrid);
            hybridEncryptionResult.Data.Metadata.IsHybrid.Should().BeTrue();
            hybridEncryptionResult.Data.Metadata.IsPostQuantum.Should().BeTrue();
            encryptionDuration.TotalSeconds.Should().BeLessThan(2.0); // Performance requirement

            var encryptedData = hybridEncryptionResult.Data.EncryptedData;
            encryptedData.PostQuantumEncryptedKey.Should().NotBeNullOrEmpty();
            encryptedData.ClassicalEncryptedKey.Should().NotBeNullOrEmpty();
            encryptedData.SymmetricEncryptedData.Should().NotBeNullOrEmpty();
            encryptedData.AlgorithmInfo.PostQuantumKemAlgorithm.Should().Be("ML-KEM-768");
            encryptedData.AlgorithmInfo.ClassicalKemAlgorithm.Should().NotBeNullOrEmpty();
            encryptedData.AlgorithmInfo.SymmetricAlgorithm.Should().Be("AES-256-GCM");

            Console.WriteLine($"Encryption completed in {encryptionDuration.TotalMilliseconds:F2}ms");
            Console.WriteLine($"Original size: {emailBytes.Length} bytes");
            Console.WriteLine($"PQC encrypted key size: {encryptedData.PostQuantumEncryptedKey.Length} bytes");
            Console.WriteLine($"Classical encrypted key size: {encryptedData.ClassicalEncryptedKey.Length} bytes");
            Console.WriteLine($"Symmetric encrypted data size: {encryptedData.SymmetricEncryptedData.Length} bytes");

            // Step 4: Hybrid Decryption
            var decryptionStartTime = DateTime.UtcNow;
            var decryptionResult = await _hybridEngine.DecryptHybridAsync(
                encryptedData,
                recipientPqcEncKeyPair.Data.PrivateKey,
                recipientClassicalEncKeyPair.Data.PrivateKey
            );
            var decryptionDuration = DateTime.UtcNow - decryptionStartTime;

            // Verify decryption success and performance
            decryptionResult.IsSuccess.Should().BeTrue();
            decryptionResult.Data.Should().NotBeNullOrEmpty();
            decryptionDuration.TotalSeconds.Should().BeLessThan(2.0); // Performance requirement

            // Step 5: Data Integrity Verification
            var decryptedContent = System.Text.Encoding.UTF8.GetString(decryptionResult.Data);
            decryptedContent.Should().Be(emailContent);

            Console.WriteLine($"Decryption completed in {decryptionDuration.TotalMilliseconds:F2}ms");
            Console.WriteLine("Content integrity verified successfully");

            // Step 6: Digital Signature Verification
            var verificationResult = await _provider.VerifySignatureAsync(
                decryptionResult.Data,
                signatureResult.Data.SignatureData,
                senderPqcSigKeyPair.Data.PublicKey
            );

            verificationResult.IsSuccess.Should().BeTrue();
            verificationResult.Data.Should().BeTrue();

            Console.WriteLine("Digital signature verification successful");

            // Step 7: Performance Metrics Collection
            var encryptionMetrics = _provider.GetLastOperationMetrics();
            encryptionMetrics.Should().NotBeNull();
            encryptionMetrics.Operation.Should().NotBeNullOrEmpty();
            encryptionMetrics.Duration.Should().BeLessThan(TimeSpan.FromSeconds(2));

            Console.WriteLine($"Final metrics - Operation: {encryptionMetrics.Operation}, Duration: {encryptionMetrics.Duration.TotalMilliseconds:F2}ms");
        }

        [Test]
        public async Task FailoverScenario_PqcFailureWithClassicalFallback_ShouldMaintainSecurity()
        {
            // Arrange - Simulate a scenario where PQC algorithms fail but classical algorithms work
            var testData = "Failover test data - critical financial information"u8.ToArray();
            
            // Generate only classical key pairs (simulating PQC failure)
            var recipientClassicalKeyPair = await _provider.GenerateKeyPairAsync("RSA-OAEP-2048", false);
            recipientClassicalKeyPair.IsSuccess.Should().BeTrue();

            // Create recipient capabilities that prefer PQC but can fall back to classical
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: false, // Simulate PQC not available
                supportedPqcKemAlgorithms: new string[0],
                supportedPqcSignatureAlgorithms: new string[0],
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048", "RSA-PSS-2048" },
                supportsHybrid: false
            );

            // Act - Algorithm selection should recommend classical fallback
            var strategyRecommendation = _algorithmSelector.RecommendEncryptionStrategy(capabilities);
            
            // Assert - Should gracefully fall back to classical
            strategyRecommendation.Strategy.Should().Be(EncryptionStrategy.ClassicalOnly);
            strategyRecommendation.ConfidenceScore.Should().BeGreaterThan(0.5f);
            strategyRecommendation.Reasoning.Should().Contain("classical");

            // Perform encryption with classical algorithms only
            var encryptionResult = await _provider.EncryptAsync(testData, recipientClassicalKeyPair.Data.PublicKey);
            encryptionResult.IsSuccess.Should().BeTrue();
            encryptionResult.Data.Metadata.IsPostQuantum.Should().BeFalse();
            encryptionResult.Data.Metadata.IsHybrid.Should().BeFalse();

            // Verify round-trip still works
            var decryptionResult = await _provider.DecryptAsync(
                encryptionResult.Data.EncryptedData,
                recipientClassicalKeyPair.Data.PrivateKey
            );

            decryptionResult.IsSuccess.Should().BeTrue();
            decryptionResult.Data.Should().BeEquivalentTo(testData);

            Console.WriteLine($"Failover scenario completed successfully");
            Console.WriteLine($"Used algorithm: {encryptionResult.Data.Algorithm}");
            Console.WriteLine($"Strategy confidence: {strategyRecommendation.ConfidenceScore:P1}");
        }

        [Test]
        public async Task PerformanceBenchmark_LargeEmailWithAttachments_ShouldMeetRequirements()
        {
            // Arrange - Simulate large email with attachments (5MB total)
            var largeEmailContent = new byte[5 * 1024 * 1024]; // 5MB
            new Random(42).NextBytes(largeEmailContent); // Use seed for reproducibility

            // Generate key pairs
            var kemKeyPair = await _provider.GenerateKeyPairAsync("ML-KEM-768", false);
            var sigKeyPair = await _provider.GenerateKeyPairAsync("ML-DSA-65", true);
            
            kemKeyPair.IsSuccess.Should().BeTrue();
            sigKeyPair.IsSuccess.Should().BeTrue();

            // Measure encryption performance
            var encryptionStartTime = DateTime.UtcNow;
            var encryptionResult = await _provider.EncryptAsync(largeEmailContent, kemKeyPair.Data.PublicKey);
            var encryptionTime = DateTime.UtcNow - encryptionStartTime;

            // Measure signing performance
            var signingStartTime = DateTime.UtcNow;
            var signatureResult = await _provider.SignAsync(largeEmailContent, sigKeyPair.Data.PrivateKey);
            var signingTime = DateTime.UtcNow - signingStartTime;

            // Measure decryption performance
            var decryptionStartTime = DateTime.UtcNow;
            var decryptionResult = await _provider.DecryptAsync(
                encryptionResult.Data.EncryptedData,
                kemKeyPair.Data.PrivateKey
            );
            var decryptionTime = DateTime.UtcNow - decryptionStartTime;

            // Measure verification performance
            var verificationStartTime = DateTime.UtcNow;
            var verificationResult = await _provider.VerifySignatureAsync(
                largeEmailContent,
                signatureResult.Data.SignatureData,
                sigKeyPair.Data.PublicKey
            );
            var verificationTime = DateTime.UtcNow - verificationStartTime;

            // Assert performance requirements (per PRD: < 2 seconds for typical email)
            encryptionResult.IsSuccess.Should().BeTrue();
            signatureResult.IsSuccess.Should().BeTrue();
            decryptionResult.IsSuccess.Should().BeTrue();
            verificationResult.IsSuccess.Should().BeTrue();

            encryptionTime.TotalSeconds.Should().BeLessThan(2.0, "Encryption should complete within 2 seconds");
            signingTime.TotalSeconds.Should().BeLessThan(2.0, "Signing should complete within 2 seconds");
            decryptionTime.TotalSeconds.Should().BeLessThan(2.0, "Decryption should complete within 2 seconds");
            verificationTime.TotalSeconds.Should().BeLessThan(0.2, "Verification should complete within 200ms");

            // Verify data integrity
            decryptionResult.Data.Should().BeEquivalentTo(largeEmailContent);
            verificationResult.Data.Should().BeTrue();

            // Log performance metrics
            Console.WriteLine($"Performance Benchmark Results for 5MB email:");
            Console.WriteLine($"  Encryption: {encryptionTime.TotalMilliseconds:F2}ms");
            Console.WriteLine($"  Signing: {signingTime.TotalMilliseconds:F2}ms");
            Console.WriteLine($"  Decryption: {decryptionTime.TotalMilliseconds:F2}ms");
            Console.WriteLine($"  Verification: {verificationTime.TotalMilliseconds:F2}ms");
            Console.WriteLine($"  Total cryptographic overhead: {(encryptionTime + signingTime + decryptionTime + verificationTime).TotalMilliseconds:F2}ms");
        }

        [Test]
        public async Task SecurityValidation_TamperDetection_ShouldDetectModifiedData()
        {
            // Arrange
            var originalMessage = "Important financial data - do not modify"u8.ToArray();
            var sigKeyPair = await _provider.GenerateKeyPairAsync("ML-DSA-65", true);
            sigKeyPair.IsSuccess.Should().BeTrue();

            // Create original signature
            var signatureResult = await _provider.SignAsync(originalMessage, sigKeyPair.Data.PrivateKey);
            signatureResult.IsSuccess.Should().BeTrue();

            // Tamper with the data
            var tamperedMessage = (byte[])originalMessage.Clone();
            tamperedMessage[0] = (byte)(tamperedMessage[0] ^ 0xFF); // Flip bits in first byte

            // Act - Verify signature with tampered data
            var verificationResult = await _provider.VerifySignatureAsync(
                tamperedMessage,
                signatureResult.Data.SignatureData,
                sigKeyPair.Data.PublicKey
            );

            // Assert - Signature should not verify
            verificationResult.IsSuccess.Should().BeTrue(); // Operation succeeded
            verificationResult.Data.Should().BeFalse(); // But signature verification failed

            // Verify original data still validates
            var originalVerification = await _provider.VerifySignatureAsync(
                originalMessage,
                signatureResult.Data.SignatureData,
                sigKeyPair.Data.PublicKey
            );

            originalVerification.IsSuccess.Should().BeTrue();
            originalVerification.Data.Should().BeTrue();

            Console.WriteLine("Tamper detection test passed - modified data correctly rejected");
        }

        [Test]
        public async Task InteroperabilityTest_DifferentAlgorithmCombinations_ShouldWorkCorrectly()
        {
            // Test multiple algorithm combinations to ensure interoperability
            var testData = "Interoperability test message"u8.ToArray();
            
            var algorithmCombinations = new[]
            {
                new { KemAlg = "ML-KEM-768", SigAlg = "ML-DSA-65", Description = "Pure PQC" },
                new { KemAlg = "RSA-OAEP-2048", SigAlg = "RSA-PSS-2048", Description = "Pure Classical" },
                new { KemAlg = "RSA-OAEP-4096", SigAlg = "RSA-PSS-4096", Description = "Strong Classical" }
            };

            foreach (var combo in algorithmCombinations)
            {
                Console.WriteLine($"Testing {combo.Description} combination: {combo.KemAlg} + {combo.SigAlg}");

                // Generate key pairs for this combination
                var kemKeyPair = await _provider.GenerateKeyPairAsync(combo.KemAlg, false);
                var sigKeyPair = await _provider.GenerateKeyPairAsync(combo.SigAlg, true);

                kemKeyPair.IsSuccess.Should().BeTrue($"KEM key generation should succeed for {combo.KemAlg}");
                sigKeyPair.IsSuccess.Should().BeTrue($"Signature key generation should succeed for {combo.SigAlg}");

                // Test encryption/decryption
                var encryptResult = await _provider.EncryptAsync(testData, kemKeyPair.Data.PublicKey);
                encryptResult.IsSuccess.Should().BeTrue($"Encryption should succeed for {combo.KemAlg}");

                var decryptResult = await _provider.DecryptAsync(encryptResult.Data.EncryptedData, kemKeyPair.Data.PrivateKey);
                decryptResult.IsSuccess.Should().BeTrue($"Decryption should succeed for {combo.KemAlg}");
                decryptResult.Data.Should().BeEquivalentTo(testData, $"Round-trip should preserve data for {combo.KemAlg}");

                // Test signing/verification
                var signResult = await _provider.SignAsync(testData, sigKeyPair.Data.PrivateKey);
                signResult.IsSuccess.Should().BeTrue($"Signing should succeed for {combo.SigAlg}");

                var verifyResult = await _provider.VerifySignatureAsync(testData, signResult.Data.SignatureData, sigKeyPair.Data.PublicKey);
                verifyResult.IsSuccess.Should().BeTrue($"Verification should succeed for {combo.SigAlg}");
                verifyResult.Data.Should().BeTrue($"Signature should be valid for {combo.SigAlg}");

                Console.WriteLine($"  ✓ {combo.Description} combination passed all tests");
            }

            Console.WriteLine("Interoperability test completed successfully");
        }

        #endregion
    }
}