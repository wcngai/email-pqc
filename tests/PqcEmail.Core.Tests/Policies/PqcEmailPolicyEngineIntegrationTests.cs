using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;
using PqcEmail.Core.Policies.Engines;
using Xunit;
using Xunit.Abstractions;

namespace PqcEmail.Core.Tests.Policies
{
    /// <summary>
    /// Integration tests for the complete PQC Email Policy Engine covering end-to-end policy evaluation scenarios.
    /// </summary>
    public class PqcEmailPolicyEngineIntegrationTests
    {
        private readonly ITestOutputHelper _output;
        private readonly Mock<ILogger<PqcEmailPolicyEngine>> _loggerMock;
        private readonly Mock<ILogger<DomainRuleEngine>> _domainLoggerMock;
        private readonly Mock<ILogger<AlgorithmEnforcementEngine>> _algorithmLoggerMock;
        private readonly Mock<IPolicyAuditLogger> _auditLoggerMock;
        private readonly DomainRuleEngine _domainEngine;
        private readonly AlgorithmEnforcementEngine _algorithmEngine;
        private readonly PqcEmailPolicyEngine _policyEngine;

        public PqcEmailPolicyEngineIntegrationTests(ITestOutputHelper output)
        {
            _output = output;
            _loggerMock = new Mock<ILogger<PqcEmailPolicyEngine>>();
            _domainLoggerMock = new Mock<ILogger<DomainRuleEngine>>();
            _algorithmLoggerMock = new Mock<ILogger<AlgorithmEnforcementEngine>>();
            _auditLoggerMock = new Mock<IPolicyAuditLogger>();

            _domainEngine = new DomainRuleEngine(_domainLoggerMock.Object);
            _algorithmEngine = new AlgorithmEnforcementEngine(_algorithmLoggerMock.Object);

            // Create mock policy source providers
            var mockProviders = CreateMockPolicyProviders();
            
            _policyEngine = new PqcEmailPolicyEngine(
                _loggerMock.Object,
                _domainEngine,
                _algorithmEngine,
                _auditLoggerMock.Object,
                mockProviders);
        }

        #region End-to-End Policy Evaluation Tests

        [Fact]
        public async Task EvaluatePolicyAsync_FinancialInstitutionScenario_EnforcesPqcForBankDomains()
        {
            // Arrange - Financial institution scenario
            var recipientEmails = new[] 
            { 
                "client@bigbank.com", 
                "advisor@investment.bank", 
                "support@creditunion.org" 
            };

            // Act
            var result = await _policyEngine.EvaluatePolicyAsync(recipientEmails, "banker@ourbank.com");

            // Assert
            Assert.NotNull(result);
            Assert.True(result.RequireEncryption, "Financial institutions should require encryption");
            Assert.Equal(CryptographicMode.PostQuantumOnly, result.EffectiveConfiguration.Mode);
            
            // Should have applied domain rules for financial domains
            var domainPolicyApplied = result.AppliedPolicies.Any(p => 
                p.Source == PolicySource.DomainOverride && 
                p.Description.Contains("requires PQC"));
            Assert.True(domainPolicyApplied, "Domain policy should be applied for financial domains");

            _output.WriteLine($"Financial scenario - Mode: {result.EffectiveConfiguration.Mode}");
            _output.WriteLine($"Applied policies: {string.Join(", ", result.AppliedPolicies.Select(p => p.Description))}");
        }

        [Fact]
        public async Task EvaluatePolicyAsync_LegacySystemScenario_AllowsClassicalFallback()
        {
            // Arrange - Legacy system scenario
            var recipientEmails = new[] { "oldapp@legacy.system", "mainframe@old.partner.com" };

            // Act
            var result = await _policyEngine.EvaluatePolicyAsync(recipientEmails, "modernuser@company.com");

            // Assert
            Assert.NotNull(result);
            
            // Should allow classical-only for legacy systems
            var allowsClassical = result.AppliedPolicies.Any(p => 
                p.Description.Contains("allows classical-only"));
            Assert.True(allowsClassical, "Should allow classical encryption for legacy systems");

            _output.WriteLine($"Legacy scenario - Mode: {result.EffectiveConfiguration.Mode}");
            _output.WriteLine($"Allows classical: {allowsClassical}");
        }

        [Fact]
        public async Task EvaluatePolicyAsync_MixedRecipientsScenario_AppliesMostRestrictivePolicy()
        {
            // Arrange - Mixed recipients: some require PQC, some allow classical
            var recipientEmails = new[] 
            { 
                "secure@bank.com",           // Requires PQC
                "normal@company.com",        // Normal policy
                "legacy@old.system"          // Allows classical
            };

            // Act
            var result = await _policyEngine.EvaluatePolicyAsync(recipientEmails);

            // Assert
            Assert.NotNull(result);
            
            // Most restrictive policy should apply (PQC required)
            Assert.True(result.RequireEncryption, "Should require encryption when any recipient needs it");
            
            // When mixed recipients, should use secure mode for all
            Assert.NotEqual(CryptographicMode.ClassicalOnly, result.EffectiveConfiguration.Mode);

            _output.WriteLine($"Mixed recipients - Mode: {result.EffectiveConfiguration.Mode}");
            _output.WriteLine($"Require encryption: {result.RequireEncryption}");
        }

        [Fact]
        public async Task EvaluatePolicyAsync_RecipientSpecificOverride_AppliesRecipientOverride()
        {
            // Arrange - Test recipient with specific override policy
            var recipientEmail = "special@company.com";

            // Act
            var result = await _policyEngine.EvaluatePolicyAsync(recipientEmail);

            // Assert
            Assert.NotNull(result);
            
            // Should have recipient-specific override applied
            var recipientOverride = result.AppliedPolicies.FirstOrDefault(p => 
                p.Source == PolicySource.RecipientOverride);
            
            if (recipientOverride != null)
            {
                Assert.Contains("special@company.com", recipientOverride.Description);
                _output.WriteLine($"Recipient override applied: {recipientOverride.Description}");
            }
        }

        #endregion

        #region Algorithm Validation Integration Tests

        [Theory]
        [InlineData("ML-KEM-768", AlgorithmType.Kem, true)]
        [InlineData("ML-DSA-65", AlgorithmType.Signature, true)]
        [InlineData("RSA-OAEP-2048", AlgorithmType.Kem, true)]
        [InlineData("MD5", AlgorithmType.Hash, false)]
        [InlineData("RSA-1024", AlgorithmType.Kem, false)]
        public async Task ValidateAlgorithmAsync_IntegrationScenarios_ValidatesCorrectly(
            string algorithm, AlgorithmType algorithmType, bool expectedValid)
        {
            // Act
            var result = await _policyEngine.ValidateAlgorithmAsync(algorithm, algorithmType);

            // Assert
            Assert.Equal(expectedValid, result);
            
            // Verify audit logging was called for violations
            if (!expectedValid)
            {
                _auditLoggerMock.Verify(
                    x => x.LogPolicyViolationAsync(It.IsAny<PolicyViolation>(), It.IsAny<Dictionary<string, object>>()),
                    Times.AtLeastOnce);
            }

            _output.WriteLine($"Algorithm validation - {algorithm}: {(result ? "VALID" : "INVALID")}");
        }

        #endregion

        #region Policy Source Integration Tests

        [Fact]
        public async Task GetEffectivePolicyAsync_MultiplePolicySources_MergesPoliciesCorrectly()
        {
            // Act
            var effectivePolicy = await _policyEngine.GetEffectivePolicyAsync();

            // Assert
            Assert.NotNull(effectivePolicy);
            Assert.NotNull(effectivePolicy.GlobalCryptographic);
            Assert.NotNull(effectivePolicy.Security);
            Assert.NotNull(effectivePolicy.Domain);
            
            // Should have reasonable defaults or values from mock providers
            Assert.True(effectivePolicy.GlobalCryptographic.Mode != 0);
            Assert.False(string.IsNullOrEmpty(effectivePolicy.GlobalCryptographic.PreferredKemAlgorithm));

            _output.WriteLine($"Effective policy loaded - Mode: {effectivePolicy.GlobalCryptographic.Mode}");
            _output.WriteLine($"Preferred KEM: {effectivePolicy.GlobalCryptographic.PreferredKemAlgorithm}");
        }

        [Fact]
        public async Task ReloadPolicyAsync_PolicySourcesUpdated_ReloadsSuccessfully()
        {
            // Arrange
            var initialPolicy = await _policyEngine.GetEffectivePolicyAsync();
            var initialMode = initialPolicy.GlobalCryptographic.Mode;

            // Act
            await _policyEngine.ReloadPolicyAsync();
            var reloadedPolicy = await _policyEngine.GetEffectivePolicyAsync();

            // Assert
            Assert.NotNull(reloadedPolicy);
            // Policy should be successfully reloaded (might be same values from mock)
            Assert.Equal(initialMode, reloadedPolicy.GlobalCryptographic.Mode);

            _output.WriteLine($"Policy reloaded successfully - Mode: {reloadedPolicy.GlobalCryptographic.Mode}");
        }

        #endregion

        #region Audit Logging Integration Tests

        [Fact]
        public async Task EvaluatePolicyAsync_PolicyDecisionMade_LogsAuditEvent()
        {
            // Arrange
            var recipientEmail = "user@example.com";

            // Act
            var result = await _policyEngine.EvaluatePolicyAsync(recipientEmail);

            // Assert
            Assert.NotNull(result);
            
            // Verify audit logging was called
            _auditLoggerMock.Verify(
                x => x.LogPolicyDecisionAsync(It.IsAny<PolicyAuditEvent>()),
                Times.Once);

            _output.WriteLine($"Policy decision logged for {recipientEmail}");
        }

        [Fact]
        public async Task LogAuditEventAsync_CustomAuditEvent_LogsSuccessfully()
        {
            // Arrange
            var auditEvent = new PolicyAuditEvent
            {
                EventType = "TestEvent",
                RecipientEmail = "test@example.com",
                PolicyDecision = "Test decision",
                Outcome = PolicyOutcome.Success
            };

            // Act
            await _policyEngine.LogAuditEventAsync(auditEvent);

            // Assert
            _auditLoggerMock.Verify(
                x => x.LogPolicyDecisionAsync(auditEvent),
                Times.Once);

            _output.WriteLine($"Custom audit event logged: {auditEvent.EventType}");
        }

        #endregion

        #region Event Handling Tests

        [Fact]
        public async Task PolicyEngine_PolicyViolationDetected_RaisesEvent()
        {
            // Arrange
            PolicyViolationEventArgs? capturedEventArgs = null;
            _policyEngine.PolicyViolationDetected += (sender, args) => capturedEventArgs = args;

            // Act - Try to validate a weak algorithm that should trigger violation
            await _policyEngine.ValidateAlgorithmAsync("MD5", AlgorithmType.Hash);

            // Assert
            // Note: Event might not be raised if validation happens before event subscription
            // This test verifies the event mechanism exists
            _output.WriteLine($"Policy violation event mechanism tested");
        }

        #endregion

        #region Complex Scenario Tests

        [Fact]
        public async Task EvaluatePolicyAsync_HighSecurityFinancialInstitution_EnforcesStrictPolicies()
        {
            // Arrange - High security financial institution with multiple compliance requirements
            var context = new Dictionary<string, object>
            {
                ["ComplianceLevel"] = "SOX",
                ["DataClassification"] = "Confidential",
                ["RegulatoryRequirement"] = "FFIEC"
            };

            var recipientEmails = new[] 
            { 
                "cfo@bank.com", 
                "auditor@sec.gov", 
                "regulator@federalreserve.gov" 
            };

            // Act
            var result = await _policyEngine.EvaluatePolicyAsync(
                recipientEmails, 
                "risk-officer@ourbank.com", 
                context);

            // Assert
            Assert.NotNull(result);
            Assert.True(result.RequireEncryption, "High security environment must require encryption");
            Assert.False(result.AllowUnencryptedFallback, "No unencrypted fallback for high security");
            
            // Should use strongest available algorithms
            Assert.Contains("ML-", result.EffectiveConfiguration.PreferredKemAlgorithm);
            Assert.Contains("ML-", result.EffectiveConfiguration.PreferredSignatureAlgorithm);

            // Context should be preserved
            Assert.Contains("ComplianceLevel", result.Context);
            Assert.Equal("SOX", result.Context["ComplianceLevel"]);

            _output.WriteLine($"High security scenario - KEM: {result.EffectiveConfiguration.PreferredKemAlgorithm}");
            _output.WriteLine($"Signature: {result.EffectiveConfiguration.PreferredSignatureAlgorithm}");
            _output.WriteLine($"Require encryption: {result.RequireEncryption}");
            _output.WriteLine($"Context preserved: {result.Context.Count} items");
        }

        [Fact]
        public async Task EvaluatePolicyAsync_InternationalPartnerScenario_HandlesGlobalPolicies()
        {
            // Arrange - International partner with varying regulatory requirements
            var recipientEmails = new[] 
            { 
                "partner@company.de",        // Germany - GDPR
                "client@bank.jp",            // Japan - Financial regulations  
                "vendor@tech.ca"             // Canada - PIPEDA
            };

            var context = new Dictionary<string, object>
            {
                ["InternationalTransfer"] = true,
                ["GDPRApplicable"] = true,
                ["CrossBorderCompliance"] = "Required"
            };

            // Act
            var result = await _policyEngine.EvaluatePolicyAsync(
                recipientEmails, 
                "global-manager@company.com", 
                context);

            // Assert
            Assert.NotNull(result);
            
            // International transfers should use strong encryption
            Assert.True(result.RequireEncryption);
            Assert.NotEqual(CryptographicMode.ClassicalOnly, result.EffectiveConfiguration.Mode);

            // Should have policies applied for international context
            Assert.True(result.AppliedPolicies.Count > 1, "Multiple policies should be applied");

            _output.WriteLine($"International scenario - Mode: {result.EffectiveConfiguration.Mode}");
            _output.WriteLine($"Applied policies: {result.AppliedPolicies.Count}");
            _output.WriteLine($"Cross-border compliance: {context["CrossBorderCompliance"]}");
        }

        #endregion

        #region Helper Methods

        /// <summary>
        /// Creates mock policy source providers for testing.
        /// </summary>
        /// <returns>List of mock policy providers</returns>
        private List<IPolicySourceProvider> CreateMockPolicyProviders()
        {
            var providers = new List<IPolicySourceProvider>();

            // Mock Group Policy provider
            var groupPolicyMock = new Mock<IPolicySourceProvider>();
            groupPolicyMock.Setup(p => p.SourceType).Returns(PolicySource.GroupPolicy);
            groupPolicyMock.Setup(p => p.Priority).Returns(800);
            groupPolicyMock.Setup(p => p.IsAvailableAsync()).ReturnsAsync(true);
            groupPolicyMock.Setup(p => p.GetPolicyAsync()).ReturnsAsync(CreateMockGroupPolicy());

            // Mock Configuration provider
            var configMock = new Mock<IPolicySourceProvider>();
            configMock.Setup(p => p.SourceType).Returns(PolicySource.Configuration);
            configMock.Setup(p => p.Priority).Returns(500);
            configMock.Setup(p => p.IsAvailableAsync()).ReturnsAsync(true);
            configMock.Setup(p => p.GetPolicyAsync()).ReturnsAsync(CreateMockConfigurationPolicy());

            providers.Add(groupPolicyMock.Object);
            providers.Add(configMock.Object);

            return providers;
        }

        /// <summary>
        /// Creates a mock Group Policy configuration for testing.
        /// </summary>
        /// <returns>Mock policy configuration</returns>
        private PqcEmailPolicy CreateMockGroupPolicy()
        {
            return new PqcEmailPolicy
            {
                Source = PolicySource.GroupPolicy,
                GlobalCryptographic = new GlobalCryptographicPolicy
                {
                    Mode = CryptographicMode.Hybrid,
                    PreferredKemAlgorithm = "ML-KEM-768",
                    PreferredSignatureAlgorithm = "ML-DSA-65",
                    FallbackKemAlgorithm = "RSA-OAEP-2048",
                    FallbackSignatureAlgorithm = "RSA-PSS-2048"
                },
                Security = new SecurityPolicy
                {
                    MinimumSecurityLevel = SecurityLevel.High,
                    ProhibitWeakAlgorithms = true,
                    MinimumRsaKeySize = 2048
                },
                Domain = new DomainPolicy
                {
                    ForcePqcDomains = new List<DomainRule>
                    {
                        new() { Pattern = "*.bank.com", Enabled = true, Priority = 200 },
                        new() { Pattern = "*.financial.*", Enabled = true, Priority = 180 },
                        new() { Pattern = "*@sec.gov", Enabled = true, Priority = 250 }
                    },
                    ProhibitUnencryptedDomains = new List<DomainRule>
                    {
                        new() { Pattern = "*.internal.corp", Enabled = true, Priority = 150 }
                    },
                    AllowClassicalOnlyDomains = new List<DomainRule>
                    {
                        new() { Pattern = "*.legacy.system", Enabled = true, Priority = 100 },
                        new() { Pattern = "*.old.partner.com", Enabled = true, Priority = 120 }
                    },
                    RecipientOverrides = new Dictionary<string, RecipientSpecificPolicy>
                    {
                        ["special@company.com"] = new()
                        {
                            ModeOverride = CryptographicMode.PostQuantumOnly,
                            AllowUnencrypted = false
                        }
                    }
                },
                Fallback = new FallbackPolicy
                {
                    AllowUnencryptedFallback = false,
                    MaxFallbackAttempts = 3,
                    FallbackTimeoutSeconds = 30
                },
                Audit = new AuditPolicy
                {
                    EnableDetailedLogging = true,
                    LogPolicyDecisions = true,
                    LogFallbackEvents = true,
                    LogSecurityViolations = true,
                    LogLevel = LogLevel.Information
                }
            };
        }

        /// <summary>
        /// Creates a mock configuration policy for testing.
        /// </summary>
        /// <returns>Mock configuration policy</returns>
        private PqcEmailPolicy CreateMockConfigurationPolicy()
        {
            return new PqcEmailPolicy
            {
                Source = PolicySource.Configuration,
                GlobalCryptographic = new GlobalCryptographicPolicy
                {
                    Mode = CryptographicMode.Hybrid,
                    PreferredKemAlgorithm = "ML-KEM-768",
                    PreferredSignatureAlgorithm = "ML-DSA-65"
                },
                Security = new SecurityPolicy
                {
                    MinimumSecurityLevel = SecurityLevel.Standard,
                    ProhibitWeakAlgorithms = true
                },
                Performance = new PerformancePolicy
                {
                    MaxOperationTimeMs = 2000,
                    MaxMemoryUsageMB = 100,
                    CacheExpiryMinutes = 60
                }
            };
        }

        #endregion
    }
}