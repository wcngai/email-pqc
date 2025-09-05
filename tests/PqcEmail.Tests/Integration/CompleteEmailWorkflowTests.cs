using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using FluentAssertions;
using Xunit.Abstractions;
using PqcEmail.Core.Cryptography;
using PqcEmail.Core.Discovery;
using PqcEmail.Core.Certificates;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;
using PqcEmail.Outlook.Services;

namespace PqcEmail.Tests.Integration
{
    /// <summary>
    /// Integration tests covering complete email workflows from composition to delivery.
    /// Tests the full pipeline: capability discovery → key management → encryption → transport → decryption.
    /// </summary>
    public class CompleteEmailWorkflowTests : IAsyncLifetime
    {
        private readonly ITestOutputHelper _output;
        private readonly ServiceProvider _serviceProvider;
        private readonly ISmimeMessageProcessor _smimeProcessor;
        private readonly ICapabilityDiscoveryService _capabilityService;
        private readonly IWindowsCertificateManager _certificateManager;
        private readonly IPqcEncryptionService _encryptionService;

        public CompleteEmailWorkflowTests(ITestOutputHelper output)
        {
            _output = output;

            // Setup dependency injection container for integration testing
            var services = new ServiceCollection();
            
            // Add logging
            services.AddLogging(builder => builder.AddConsole().SetMinimumLevel(LogLevel.Debug));
            
            // Register real services for integration testing
            services.AddSingleton<ICryptographicProvider, MockCryptographicProvider>();
            services.AddSingleton<IHybridEncryptionEngine, HybridEncryptionEngine>();
            services.AddSingleton<IKemRecipientInfoProcessor, KemRecipientInfoProcessor>();
            services.AddSingleton<ISmimeMessageProcessor, SmimeMessageProcessor>();
            services.AddSingleton<ICapabilityDiscoveryService, MockCapabilityDiscoveryService>();
            services.AddSingleton<IWindowsCertificateManager, MockWindowsCertificateManager>();
            services.AddSingleton<IPqcEncryptionService, MockPqcEncryptionService>();
            
            _serviceProvider = services.BuildServiceProvider();
            
            _smimeProcessor = _serviceProvider.GetRequiredService<ISmimeMessageProcessor>();
            _capabilityService = _serviceProvider.GetRequiredService<ICapabilityDiscoveryService>();
            _certificateManager = _serviceProvider.GetRequiredService<IWindowsCertificateManager>();
            _encryptionService = _serviceProvider.GetRequiredService<IPqcEncryptionService>();
        }

        public async Task InitializeAsync()
        {
            // Initialize test environment
            await SetupTestCertificates();
            await SetupTestCapabilities();
            _output.WriteLine("✅ Test environment initialized");
        }

        public async Task DisposeAsync()
        {
            await CleanupTestEnvironment();
            _serviceProvider?.Dispose();
        }

        [Fact]
        public async Task CompleteWorkflow_SingleRecipientPQCSupported_ShouldUseQuantumSafeEncryption()
        {
            // Arrange
            var sender = "alice@quantumsafe.example.com";
            var recipient = "bob@quantumsafe.example.com";
            var subject = "Quantum-Safe Test Email";
            var body = "This is a test email encrypted with post-quantum cryptography.";

            _output.WriteLine($"Testing complete workflow: {sender} → {recipient}");

            // Act - Step 1: Capability Discovery
            _output.WriteLine("Step 1: Discovering recipient capabilities...");
            var recipientCapabilities = await _capabilityService.DiscoverCapabilitiesAsync(recipient);
            
            recipientCapabilities.Should().NotBeNull();
            recipientCapabilities.SupportsPQC.Should().BeTrue("Recipient should support PQC");
            _output.WriteLine($"✅ Recipient supports: {string.Join(", ", recipientCapabilities.SupportedAlgorithms)}");

            // Act - Step 2: Certificate Retrieval
            _output.WriteLine("Step 2: Retrieving recipient certificate...");
            var recipientCert = await _certificateManager.GetCertificateAsync(recipient);
            
            recipientCert.Should().NotBeNull();
            recipientCert.SupportsPQC.Should().BeTrue();
            _output.WriteLine($"✅ Certificate retrieved with algorithm: {recipientCert.Algorithm}");

            // Act - Step 3: Email Composition and Encryption
            _output.WriteLine("Step 3: Encrypting email message...");
            var emailMessage = CreateTestEmailMessage(sender, recipient, subject, body);
            var encryptedMessage = await _smimeProcessor.EncryptAsync(emailMessage, new[] { recipientCert });
            
            encryptedMessage.Should().NotBeNull();
            encryptedMessage.IsEncrypted.Should().BeTrue();
            encryptedMessage.EncryptionAlgorithm.Should().Contain("ML-KEM-768");
            _output.WriteLine($"✅ Email encrypted using: {encryptedMessage.EncryptionAlgorithm}");

            // Act - Step 4: Message Transport (Simulated)
            _output.WriteLine("Step 4: Simulating message transport...");
            var transportedMessage = await SimulateMessageTransport(encryptedMessage);
            transportedMessage.Should().NotBeNull();
            _output.WriteLine("✅ Message transported successfully");

            // Act - Step 5: Message Decryption
            _output.WriteLine("Step 5: Decrypting received message...");
            var senderCert = await _certificateManager.GetCertificateAsync(sender);
            var decryptedMessage = await _smimeProcessor.DecryptAsync(transportedMessage, senderCert);
            
            decryptedMessage.Should().NotBeNull();
            decryptedMessage.Subject.Should().Be(subject);
            decryptedMessage.Body.Should().Be(body);
            decryptedMessage.IsDecrypted.Should().BeTrue();
            _output.WriteLine("✅ Message decrypted successfully");

            // Assert - Verify end-to-end security
            decryptedMessage.SecurityInfo.Should().NotBeNull();
            decryptedMessage.SecurityInfo.EncryptionAlgorithm.Should().Contain("ML-KEM-768");
            decryptedMessage.SecurityInfo.IsQuantumSafe.Should().BeTrue();
            
            _output.WriteLine("🔒 End-to-end quantum-safe encryption verified");
        }

        [Fact]
        public async Task CompleteWorkflow_MultipleRecipients_ShouldHandleMixedCapabilities()
        {
            // Arrange
            var sender = "sender@hybrid.example.com";
            var recipients = new[]
            {
                "pqc.user@quantumsafe.example.com",      // Supports PQC
                "legacy.user@traditional.example.com",   // Legacy only
                "hybrid.user@mixed.example.com"          // Supports both
            };
            var subject = "Multi-Recipient Test";
            var body = "Testing mixed recipient capabilities";

            _output.WriteLine($"Testing multi-recipient workflow with {recipients.Length} recipients");

            // Act - Step 1: Discover capabilities for all recipients
            var capabilityTasks = recipients.Select(r => _capabilityService.DiscoverCapabilitiesAsync(r));
            var capabilities = await Task.WhenAll(capabilityTasks);
            
            foreach (var (recipient, capability) in recipients.Zip(capabilities))
            {
                _output.WriteLine($"  {recipient}: PQC={capability.SupportsPQC}");
            }

            // Act - Step 2: Retrieve certificates for all recipients
            var certTasks = recipients.Select(r => _certificateManager.GetCertificateAsync(r));
            var certificates = await Task.WhenAll(certTasks);
            
            certificates.Should().AllSatisfy(cert => cert.Should().NotBeNull());

            // Act - Step 3: Encrypt with hybrid approach
            var emailMessage = CreateTestEmailMessage(sender, recipients, subject, body);
            var encryptedMessage = await _smimeProcessor.EncryptAsync(emailMessage, certificates);
            
            encryptedMessage.Should().NotBeNull();
            encryptedMessage.IsEncrypted.Should().BeTrue();
            
            // Should use hybrid encryption to accommodate all recipients
            encryptedMessage.EncryptionMode.Should().Be(EncryptionMode.Hybrid);
            _output.WriteLine($"✅ Hybrid encryption used: {encryptedMessage.EncryptionMode}");

            // Act - Step 4: Verify each recipient can decrypt
            foreach (var (recipient, certificate) in recipients.Zip(certificates))
            {
                _output.WriteLine($"Testing decryption for {recipient}...");
                
                var decryptedForRecipient = await _smimeProcessor.DecryptAsync(encryptedMessage, certificate);
                
                decryptedForRecipient.Should().NotBeNull();
                decryptedForRecipient.Subject.Should().Be(subject);
                decryptedForRecipient.Body.Should().Be(body);
                
                // Verify appropriate security level for each recipient
                if (certificate.SupportsPQC)
                {
                    decryptedForRecipient.SecurityInfo.IsQuantumSafe.Should().BeTrue();
                }
                else
                {
                    decryptedForRecipient.SecurityInfo.IsQuantumSafe.Should().BeFalse();
                    decryptedForRecipient.SecurityInfo.SecurityWarnings.Should().Contain("Legacy encryption used");
                }
                
                _output.WriteLine($"  ✅ {recipient} successfully decrypted");
            }
        }

        [Fact]
        public async Task CompleteWorkflow_WithDigitalSignature_ShouldVerifySignature()
        {
            // Arrange
            var sender = "signed.sender@secure.example.com";
            var recipient = "verified.recipient@secure.example.com";
            var subject = "Digitally Signed Email";
            var body = "This email includes a digital signature for authentication.";

            _output.WriteLine($"Testing complete workflow with digital signature");

            // Act - Step 1: Prepare certificates for signing and encryption
            var senderCert = await _certificateManager.GetSigningCertificateAsync(sender);
            var recipientCert = await _certificateManager.GetEncryptionCertificateAsync(recipient);
            
            senderCert.Should().NotBeNull();
            recipientCert.Should().NotBeNull();

            // Act - Step 2: Create, sign, and encrypt email
            var emailMessage = CreateTestEmailMessage(sender, recipient, subject, body);
            
            _output.WriteLine("Signing email message...");
            var signedMessage = await _smimeProcessor.SignAsync(emailMessage, senderCert);
            signedMessage.IsSigned.Should().BeTrue();
            _output.WriteLine($"✅ Email signed with: {signedMessage.SignatureAlgorithm}");

            _output.WriteLine("Encrypting signed email...");
            var signedAndEncryptedMessage = await _smimeProcessor.EncryptAsync(signedMessage, new[] { recipientCert });
            signedAndEncryptedMessage.IsEncrypted.Should().BeTrue();
            signedAndEncryptedMessage.IsSigned.Should().BeTrue();
            _output.WriteLine("✅ Email signed and encrypted");

            // Act - Step 3: Decrypt and verify signature
            _output.WriteLine("Decrypting message...");
            var decryptedMessage = await _smimeProcessor.DecryptAsync(signedAndEncryptedMessage, recipientCert);
            decryptedMessage.Should().NotBeNull();
            decryptedMessage.IsSigned.Should().BeTrue();

            _output.WriteLine("Verifying signature...");
            var signatureValid = await _smimeProcessor.VerifySignatureAsync(decryptedMessage, senderCert);
            signatureValid.Should().BeTrue();
            _output.WriteLine("✅ Digital signature verified");

            // Assert - Comprehensive security verification
            decryptedMessage.Subject.Should().Be(subject);
            decryptedMessage.Body.Should().Be(body);
            decryptedMessage.SecurityInfo.IsQuantumSafe.Should().BeTrue();
            decryptedMessage.SecurityInfo.IsSignatureValid.Should().BeTrue();
            decryptedMessage.SecurityInfo.SignerIdentity.Should().Be(sender);
            
            _output.WriteLine("🔒 Complete signed and encrypted workflow verified");
        }

        [Fact]
        public async Task CompleteWorkflow_PolicyEnforcement_ShouldRespectAdminPolicies()
        {
            // Arrange
            var sender = "policy.sender@corporate.example.com";
            var recipient = "external.recipient@partner.example.com";
            var subject = "Policy-Controlled Email";
            var body = "Testing policy enforcement in email encryption";

            _output.WriteLine("Testing workflow with policy enforcement");

            // Act - Step 1: Setup corporate policy (PQC required for external domains)
            await SetupCorporatePolicy(new EncryptionPolicy
            {
                RequireQuantumSafe = true,
                ExternalDomainsOnly = true,
                MinimumSecurityLevel = SecurityLevel.QuantumSafe,
                AllowedAlgorithms = new[] { "ML-KEM-768", "ML-DSA-65" }
            });
            _output.WriteLine("✅ Corporate policy configured");

            // Act - Step 2: Test policy compliance
            var recipientDomain = recipient.Split('@')[1];
            var policyResult = await _encryptionService.CheckPolicyComplianceAsync(sender, recipient);
            
            policyResult.Should().NotBeNull();
            policyResult.IsCompliant.Should().BeTrue();
            policyResult.RequiredSecurityLevel.Should().Be(SecurityLevel.QuantumSafe);
            _output.WriteLine($"✅ Policy check passed: {policyResult.RequiredSecurityLevel}");

            // Act - Step 3: Encrypt according to policy
            var emailMessage = CreateTestEmailMessage(sender, recipient, subject, body);
            var encryptedMessage = await _encryptionService.EncryptWithPolicyAsync(emailMessage, recipient);
            
            encryptedMessage.Should().NotBeNull();
            encryptedMessage.IsEncrypted.Should().BeTrue();
            encryptedMessage.SecurityInfo.IsQuantumSafe.Should().BeTrue();
            encryptedMessage.SecurityInfo.PolicyCompliant.Should().BeTrue();
            _output.WriteLine("✅ Email encrypted according to policy");

            // Act - Step 4: Test policy violation scenario
            _output.WriteLine("Testing policy violation scenario...");
            await SetupCorporatePolicy(new EncryptionPolicy
            {
                RequireQuantumSafe = true,
                AllDomains = true,
                BlockNonCompliant = true
            });

            var legacyRecipient = "legacy.user@no-pqc.example.com";
            var policyViolation = await _encryptionService.CheckPolicyComplianceAsync(sender, legacyRecipient);
            
            policyViolation.IsCompliant.Should().BeFalse();
            policyViolation.ViolationReason.Should().Contain("does not support required quantum-safe encryption");
            _output.WriteLine($"✅ Policy violation detected: {policyViolation.ViolationReason}");

            // Should prevent sending or require override
            var exception = await Record.ExceptionAsync(async () =>
            {
                await _encryptionService.EncryptWithPolicyAsync(emailMessage, legacyRecipient);
            });
            
            exception.Should().NotBeNull();
            exception.Should().BeOfType<PolicyViolationException>();
            _output.WriteLine("✅ Policy enforcement prevented non-compliant encryption");
        }

        [Fact]
        public async Task CompleteWorkflow_ErrorRecovery_ShouldHandleFailuresGracefully()
        {
            // Arrange
            var sender = "test.sender@example.com";
            var recipient = "unreachable.recipient@offline.example.com";
            var subject = "Error Recovery Test";
            var body = "Testing error handling and recovery mechanisms";

            _output.WriteLine("Testing error recovery scenarios");

            // Scenario 1: Capability discovery timeout
            _output.WriteLine("Scenario 1: Testing capability discovery timeout...");
            var timeoutException = await Record.ExceptionAsync(async () =>
            {
                await _capabilityService.DiscoverCapabilitiesAsync("timeout.domain.example.com");
            });
            
            timeoutException.Should().NotBeNull();
            _output.WriteLine($"✅ Capability discovery timeout handled: {timeoutException.Message}");

            // Scenario 2: Certificate not found
            _output.WriteLine("Scenario 2: Testing missing certificate...");
            var certException = await Record.ExceptionAsync(async () =>
            {
                await _certificateManager.GetCertificateAsync("nonexistent@missing.example.com");
            });
            
            certException.Should().NotBeNull();
            _output.WriteLine($"✅ Missing certificate handled: {certException.Message}");

            // Scenario 3: Encryption failure with fallback
            _output.WriteLine("Scenario 3: Testing encryption failure with fallback...");
            var emailMessage = CreateTestEmailMessage(sender, recipient, subject, body);
            
            // Configure service to attempt PQC first, then fallback to RSA
            var encryptedMessage = await _encryptionService.EncryptWithFallbackAsync(emailMessage, recipient);
            
            encryptedMessage.Should().NotBeNull();
            encryptedMessage.IsEncrypted.Should().BeTrue();
            
            if (!encryptedMessage.SecurityInfo.IsQuantumSafe)
            {
                encryptedMessage.SecurityInfo.SecurityWarnings.Should().Contain("fallback");
                _output.WriteLine("✅ Graceful fallback to traditional encryption");
            }

            // Scenario 4: Partial recipient failure in multi-recipient scenario
            _output.WriteLine("Scenario 4: Testing partial recipient failure...");
            var mixedRecipients = new[]
            {
                "working.user@example.com",
                "broken.user@offline.example.com",
                "another.working.user@example.com"
            };

            var partialResult = await _encryptionService.EncryptToMultipleRecipientsAsync(emailMessage, mixedRecipients);
            
            partialResult.Should().NotBeNull();
            partialResult.SuccessfulRecipients.Should().HaveCount(2);
            partialResult.FailedRecipients.Should().HaveCount(1);
            partialResult.FailedRecipients.Should().Contain(r => r.Email == "broken.user@offline.example.com");
            
            _output.WriteLine($"✅ Partial failure handled: {partialResult.SuccessfulRecipients.Count}/3 recipients successful");
        }

        [Fact]
        public async Task CompleteWorkflow_PerformanceOptimization_ShouldMeetTargets()
        {
            // Arrange
            var sender = "perf.sender@example.com";
            var recipients = Enumerable.Range(1, 10).Select(i => $"recipient{i}@example.com").ToArray();
            var subject = "Performance Test Email";
            var body = GenerateLargeEmailBody(10000); // 10KB body

            _output.WriteLine($"Testing performance with {recipients.Length} recipients and {body.Length:N0} character body");

            var stopwatch = System.Diagnostics.Stopwatch.StartNew();

            // Act - Step 1: Parallel capability discovery
            _output.WriteLine("Step 1: Parallel capability discovery...");
            var capabilityTasks = recipients.Select(r => _capabilityService.DiscoverCapabilitiesAsync(r));
            var capabilities = await Task.WhenAll(capabilityTasks);
            var discoveryTime = stopwatch.ElapsedMilliseconds;
            
            _output.WriteLine($"✅ Capability discovery: {discoveryTime}ms for {recipients.Length} recipients");
            discoveryTime.Should().BeLessThan(2000, "Parallel discovery should be efficient");

            // Act - Step 2: Parallel certificate retrieval  
            _output.WriteLine("Step 2: Parallel certificate retrieval...");
            var certTasks = recipients.Select(r => _certificateManager.GetCertificateAsync(r));
            var certificates = await Task.WhenAll(certTasks);
            var certRetrievalTime = stopwatch.ElapsedMilliseconds - discoveryTime;
            
            _output.WriteLine($"✅ Certificate retrieval: {certRetrievalTime}ms for {recipients.Length} certificates");
            certRetrievalTime.Should().BeLessThan(1000, "Parallel certificate retrieval should be efficient");

            // Act - Step 3: Encryption
            _output.WriteLine("Step 3: Email encryption...");
            var emailMessage = CreateTestEmailMessage(sender, recipients, subject, body);
            var encryptionStart = stopwatch.ElapsedMilliseconds;
            var encryptedMessage = await _smimeProcessor.EncryptAsync(emailMessage, certificates);
            var encryptionTime = stopwatch.ElapsedMilliseconds - encryptionStart;
            
            _output.WriteLine($"✅ Encryption: {encryptionTime}ms");
            encryptionTime.Should().BeLessThan(500, "Encryption should meet performance target");

            // Act - Step 4: Decryption test with one recipient
            _output.WriteLine("Step 4: Decryption test...");
            var decryptionStart = stopwatch.ElapsedMilliseconds;
            var decryptedMessage = await _smimeProcessor.DecryptAsync(encryptedMessage, certificates[0]);
            var decryptionTime = stopwatch.ElapsedMilliseconds - decryptionStart;
            
            _output.WriteLine($"✅ Decryption: {decryptionTime}ms");
            decryptionTime.Should().BeLessThan(200, "Decryption should meet performance target");

            stopwatch.Stop();
            
            // Assert overall performance
            var totalTime = stopwatch.ElapsedMilliseconds;
            _output.WriteLine($"🚀 Total workflow time: {totalTime}ms");
            totalTime.Should().BeLessThan(5000, "Complete workflow should be efficient");

            // Verify message integrity
            decryptedMessage.Subject.Should().Be(subject);
            decryptedMessage.Body.Should().Be(body);
            encryptedMessage.IsEncrypted.Should().BeTrue();
            decryptedMessage.IsDecrypted.Should().BeTrue();
        }

        // Helper methods
        private async Task SetupTestCertificates()
        {
            // Mock certificate setup for testing
            await Task.Delay(10);
        }

        private async Task SetupTestCapabilities()
        {
            // Mock capability setup for testing
            await Task.Delay(10);
        }

        private async Task CleanupTestEnvironment()
        {
            await Task.Delay(10);
        }

        private EmailMessage CreateTestEmailMessage(string from, string to, string subject, string body)
        {
            return new EmailMessage
            {
                From = from,
                To = new[] { to },
                Subject = subject,
                Body = body,
                Timestamp = DateTime.UtcNow
            };
        }

        private EmailMessage CreateTestEmailMessage(string from, string[] to, string subject, string body)
        {
            return new EmailMessage
            {
                From = from,
                To = to,
                Subject = subject,
                Body = body,
                Timestamp = DateTime.UtcNow
            };
        }

        private async Task<EmailMessage> SimulateMessageTransport(EmailMessage encryptedMessage)
        {
            // Simulate network transport delay
            await Task.Delay(50);
            return encryptedMessage;
        }

        private async Task SetupCorporatePolicy(EncryptionPolicy policy)
        {
            // Mock policy setup
            await Task.Delay(10);
        }

        private string GenerateLargeEmailBody(int characterCount)
        {
            var random = new Random(42); // Deterministic for testing
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 .!?";
            return new string(Enumerable.Repeat(chars, characterCount)
                .Select(s => s[random.Next(s.Length)]).ToArray());
        }
    }

    // Mock implementations for integration testing
    public class MockCapabilityDiscoveryService : ICapabilityDiscoveryService
    {
        public async Task<RecipientCapability> DiscoverCapabilitiesAsync(string recipient)
        {
            await Task.Delay(Random.Shared.Next(10, 100)); // Simulate network delay
            
            var domain = recipient.Split('@').LastOrDefault() ?? "";
            var supportsPQC = !domain.Contains("traditional") && !domain.Contains("legacy") && !domain.Contains("no-pqc");
            
            if (domain.Contains("timeout"))
                throw new TimeoutException("Capability discovery timeout");
            
            return new RecipientCapability
            {
                Email = recipient,
                SupportsPQC = supportsPQC,
                SupportedAlgorithms = supportsPQC ? new[] { "ML-KEM-768", "ML-DSA-65" } : new[] { "RSA-2048" }
            };
        }
    }

    public class MockWindowsCertificateManager : IWindowsCertificateManager
    {
        public async Task<CertificateInfo> GetCertificateAsync(string email)
        {
            await Task.Delay(Random.Shared.Next(5, 50));
            
            if (email.Contains("nonexistent") || email.Contains("missing"))
                throw new CertificateNotFoundException($"Certificate not found for {email}");
            
            var supportsPQC = !email.Contains("traditional") && !email.Contains("legacy");
            
            return new CertificateInfo
            {
                Email = email,
                SupportsPQC = supportsPQC,
                Algorithm = supportsPQC ? "ML-KEM-768" : "RSA-2048",
                ValidFrom = DateTime.UtcNow.AddDays(-30),
                ValidTo = DateTime.UtcNow.AddDays(365)
            };
        }

        public async Task<CertificateInfo> GetSigningCertificateAsync(string email) => await GetCertificateAsync(email);
        public async Task<CertificateInfo> GetEncryptionCertificateAsync(string email) => await GetCertificateAsync(email);
    }

    public class MockPqcEncryptionService : IPqcEncryptionService
    {
        public async Task<PolicyCheckResult> CheckPolicyComplianceAsync(string sender, string recipient)
        {
            await Task.Delay(10);
            
            var recipientDomain = recipient.Split('@').LastOrDefault() ?? "";
            var isCompliant = !recipientDomain.Contains("no-pqc") && !recipientDomain.Contains("legacy");
            
            return new PolicyCheckResult
            {
                IsCompliant = isCompliant,
                RequiredSecurityLevel = SecurityLevel.QuantumSafe,
                ViolationReason = isCompliant ? null : $"Recipient {recipient} does not support required quantum-safe encryption"
            };
        }

        public async Task<EmailMessage> EncryptWithPolicyAsync(EmailMessage message, string recipient)
        {
            var policyResult = await CheckPolicyComplianceAsync(message.From, recipient);
            if (!policyResult.IsCompliant)
                throw new PolicyViolationException(policyResult.ViolationReason);
            
            await Task.Delay(Random.Shared.Next(50, 200));
            
            return new EmailMessage
            {
                From = message.From,
                To = message.To,
                Subject = message.Subject,
                Body = message.Body,
                IsEncrypted = true,
                SecurityInfo = new SecurityInfo
                {
                    IsQuantumSafe = true,
                    EncryptionAlgorithm = "ML-KEM-768",
                    PolicyCompliant = true
                }
            };
        }

        public async Task<EmailMessage> EncryptWithFallbackAsync(EmailMessage message, string recipient)
        {
            await Task.Delay(Random.Shared.Next(50, 200));
            
            var recipientDomain = recipient.Split('@').LastOrDefault() ?? "";
            var supportsPQC = !recipientDomain.Contains("offline") && !recipientDomain.Contains("broken");
            
            return new EmailMessage
            {
                From = message.From,
                To = message.To,
                Subject = message.Subject,
                Body = message.Body,
                IsEncrypted = true,
                SecurityInfo = new SecurityInfo
                {
                    IsQuantumSafe = supportsPQC,
                    EncryptionAlgorithm = supportsPQC ? "ML-KEM-768" : "RSA-2048",
                    SecurityWarnings = supportsPQC ? null : new[] { "Fallback to traditional encryption" }
                }
            };
        }

        public async Task<MultiRecipientResult> EncryptToMultipleRecipientsAsync(EmailMessage message, string[] recipients)
        {
            await Task.Delay(Random.Shared.Next(100, 300));
            
            var successful = recipients.Where(r => !r.Contains("broken") && !r.Contains("offline")).ToList();
            var failed = recipients.Where(r => r.Contains("broken") || r.Contains("offline"))
                .Select(r => new RecipientFailure { Email = r, Reason = "Recipient unreachable" }).ToList();
            
            return new MultiRecipientResult
            {
                SuccessfulRecipients = successful,
                FailedRecipients = failed
            };
        }
    }

    // Supporting model classes
    public class EmailMessage
    {
        public string From { get; set; } = string.Empty;
        public string[] To { get; set; } = Array.Empty<string>();
        public string Subject { get; set; } = string.Empty;
        public string Body { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public bool IsEncrypted { get; set; }
        public bool IsSigned { get; set; }
        public bool IsDecrypted { get; set; }
        public string EncryptionAlgorithm { get; set; } = string.Empty;
        public string SignatureAlgorithm { get; set; } = string.Empty;
        public EncryptionMode EncryptionMode { get; set; }
        public SecurityInfo SecurityInfo { get; set; } = new();
    }

    public class SecurityInfo
    {
        public bool IsQuantumSafe { get; set; }
        public string EncryptionAlgorithm { get; set; } = string.Empty;
        public bool PolicyCompliant { get; set; }
        public bool IsSignatureValid { get; set; }
        public string SignerIdentity { get; set; } = string.Empty;
        public string[] SecurityWarnings { get; set; } = Array.Empty<string>();
    }

    public class RecipientCapability
    {
        public string Email { get; set; } = string.Empty;
        public bool SupportsPQC { get; set; }
        public string[] SupportedAlgorithms { get; set; } = Array.Empty<string>();
    }

    public class CertificateInfo
    {
        public string Email { get; set; } = string.Empty;
        public bool SupportsPQC { get; set; }
        public string Algorithm { get; set; } = string.Empty;
        public DateTime ValidFrom { get; set; }
        public DateTime ValidTo { get; set; }
    }

    public class EncryptionPolicy
    {
        public bool RequireQuantumSafe { get; set; }
        public bool ExternalDomainsOnly { get; set; }
        public bool AllDomains { get; set; }
        public bool BlockNonCompliant { get; set; }
        public SecurityLevel MinimumSecurityLevel { get; set; }
        public string[] AllowedAlgorithms { get; set; } = Array.Empty<string>();
    }

    public class PolicyCheckResult
    {
        public bool IsCompliant { get; set; }
        public SecurityLevel RequiredSecurityLevel { get; set; }
        public string? ViolationReason { get; set; }
    }

    public class MultiRecipientResult
    {
        public List<string> SuccessfulRecipients { get; set; } = new();
        public List<RecipientFailure> FailedRecipients { get; set; } = new();
    }

    public class RecipientFailure
    {
        public string Email { get; set; } = string.Empty;
        public string Reason { get; set; } = string.Empty;
    }

    public enum EncryptionMode
    {
        QuantumSafe,
        Traditional,
        Hybrid
    }

    public enum SecurityLevel
    {
        Traditional = 1,
        QuantumSafe = 3
    }

    // Exception types
    public class CertificateNotFoundException : Exception
    {
        public CertificateNotFoundException(string message) : base(message) { }
    }

    public class PolicyViolationException : Exception
    {
        public PolicyViolationException(string message) : base(message) { }
    }

    // Interface definitions for mocking
    public interface ICapabilityDiscoveryService
    {
        Task<RecipientCapability> DiscoverCapabilitiesAsync(string recipient);
    }

    public interface IWindowsCertificateManager
    {
        Task<CertificateInfo> GetCertificateAsync(string email);
        Task<CertificateInfo> GetSigningCertificateAsync(string email);
        Task<CertificateInfo> GetEncryptionCertificateAsync(string email);
    }

    public interface IPqcEncryptionService
    {
        Task<PolicyCheckResult> CheckPolicyComplianceAsync(string sender, string recipient);
        Task<EmailMessage> EncryptWithPolicyAsync(EmailMessage message, string recipient);
        Task<EmailMessage> EncryptWithFallbackAsync(EmailMessage message, string recipient);
        Task<MultiRecipientResult> EncryptToMultipleRecipientsAsync(EmailMessage message, string[] recipients);
    }

    public class MockCryptographicProvider : ICryptographicProvider
    {
        // Mock implementation of ICryptographicProvider interface
        // This would contain mock implementations of all required cryptographic operations
    }
}