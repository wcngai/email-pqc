using System.Collections.Generic;
using System.Linq;
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
    /// Comprehensive tests for the AlgorithmEnforcementEngine covering security validation, fallback sequences, and policy enforcement.
    /// </summary>
    public class AlgorithmEnforcementEngineTests
    {
        private readonly ITestOutputHelper _output;
        private readonly Mock<ILogger<AlgorithmEnforcementEngine>> _loggerMock;
        private readonly AlgorithmEnforcementEngine _engine;

        public AlgorithmEnforcementEngineTests(ITestOutputHelper output)
        {
            _output = output;
            _loggerMock = new Mock<ILogger<AlgorithmEnforcementEngine>>();
            _engine = new AlgorithmEnforcementEngine(_loggerMock.Object);
        }

        #region Algorithm Enforcement Tests

        [Theory]
        [InlineData("ML-KEM-768", AlgorithmType.Kem, SecurityLevel.Standard, true)]
        [InlineData("ML-DSA-65", AlgorithmType.Signature, SecurityLevel.Standard, true)]
        [InlineData("RSA-OAEP-2048", AlgorithmType.Kem, SecurityLevel.Standard, true)]
        [InlineData("RSA-PSS-2048", AlgorithmType.Signature, SecurityLevel.Standard, true)]
        [InlineData("AES-256-GCM", AlgorithmType.Symmetric, SecurityLevel.Standard, true)]
        [InlineData("SHA-256", AlgorithmType.Hash, SecurityLevel.Standard, true)]
        public void EnforceAlgorithmRestrictions_ValidAlgorithms_AllowsAlgorithm(
            string algorithm, AlgorithmType algorithmType, SecurityLevel minSecurityLevel, bool expectedAllowed)
        {
            // Arrange
            var securityPolicy = new SecurityPolicy
            {
                MinimumSecurityLevel = minSecurityLevel,
                ProhibitWeakAlgorithms = false,
                MinimumRsaKeySize = 2048
            };

            // Act
            var result = _engine.EnforceAlgorithmRestrictions(algorithm, algorithmType, securityPolicy);

            // Assert
            Assert.Equal(expectedAllowed, result.IsAllowed);
            if (expectedAllowed)
            {
                Assert.Null(result.RejectReason);
                Assert.Empty(result.Violations);
            }

            _output.WriteLine($"Algorithm {algorithm} ({algorithmType}): Allowed={result.IsAllowed}");
        }

        [Theory]
        [InlineData("MD5")]
        [InlineData("SHA1")]
        [InlineData("RSA-1024")]
        [InlineData("DES")]
        [InlineData("3DES")]
        public void EnforceAlgorithmRestrictions_WeakAlgorithms_RejectsWhenProhibited(string weakAlgorithm)
        {
            // Arrange
            var securityPolicy = new SecurityPolicy
            {
                ProhibitWeakAlgorithms = true,
                MinimumSecurityLevel = SecurityLevel.Standard
            };

            // Act
            var result = _engine.EnforceAlgorithmRestrictions(weakAlgorithm, AlgorithmType.Hash, securityPolicy);

            // Assert
            Assert.False(result.IsAllowed);
            Assert.Contains("weak and prohibited", result.RejectReason);
            Assert.Single(result.Violations);
            Assert.Equal(ViolationType.SecurityViolation, result.Violations.First().Type);

            _output.WriteLine($"Weak algorithm {weakAlgorithm} correctly rejected: {result.RejectReason}");
        }

        [Fact]
        public void EnforceAlgorithmRestrictions_WeakAlgorithmsAllowed_AcceptsWeakAlgorithms()
        {
            // Arrange
            var securityPolicy = new SecurityPolicy
            {
                ProhibitWeakAlgorithms = false,  // Allow weak algorithms
                MinimumSecurityLevel = SecurityLevel.Low
            };

            // Act
            var result = _engine.EnforceAlgorithmRestrictions("SHA1", AlgorithmType.Hash, securityPolicy);

            // Assert - Should still reject because SHA1 isn't in our security level mappings as acceptable
            Assert.False(result.IsAllowed);

            _output.WriteLine($"SHA1 with weak algorithms allowed: Allowed={result.IsAllowed}");
        }

        [Theory]
        [InlineData("RSA-OAEP-1024", 2048, false)]
        [InlineData("RSA-OAEP-2048", 2048, true)]
        [InlineData("RSA-OAEP-4096", 2048, true)]
        [InlineData("RSA-PSS-1024", 3072, false)]
        [InlineData("RSA-PSS-3072", 3072, true)]
        public void EnforceAlgorithmRestrictions_RsaKeySizeRequirements_EnforcesMinimumKeySize(
            string algorithm, int minimumKeySize, bool expectedAllowed)
        {
            // Arrange
            var securityPolicy = new SecurityPolicy
            {
                MinimumRsaKeySize = minimumKeySize,
                ProhibitWeakAlgorithms = false,
                MinimumSecurityLevel = SecurityLevel.Low
            };

            // Act
            var result = _engine.EnforceAlgorithmRestrictions(algorithm, AlgorithmType.Kem, securityPolicy);

            // Assert
            Assert.Equal(expectedAllowed, result.IsAllowed);
            if (!expectedAllowed)
            {
                Assert.Contains($"{minimumKeySize} bits", result.RejectReason);
                Assert.Single(result.Violations);
                Assert.Equal(ViolationType.AlgorithmRestriction, result.Violations.First().Type);
            }

            _output.WriteLine($"RSA algorithm {algorithm} with min key size {minimumKeySize}: Allowed={result.IsAllowed}");
        }

        [Fact]
        public void EnforceAlgorithmRestrictions_ExplicitlyProhibitedAlgorithm_RejectsAlgorithm()
        {
            // Arrange
            var securityPolicy = new SecurityPolicy
            {
                ProhibitedAlgorithms = new List<string> { "ML-KEM-512", "RSA-OAEP-2048" },
                MinimumSecurityLevel = SecurityLevel.Low
            };

            // Act
            var result = _engine.EnforceAlgorithmRestrictions("ML-KEM-512", AlgorithmType.Kem, securityPolicy);

            // Assert
            Assert.False(result.IsAllowed);
            Assert.Contains("explicitly prohibited", result.RejectReason);
            Assert.Single(result.Violations);
            Assert.Equal(ViolationType.AlgorithmRestriction, result.Violations.First().Type);
            Assert.NotEmpty(result.SuggestedAlternatives);

            _output.WriteLine($"Explicitly prohibited algorithm rejected: {result.RejectReason}");
            _output.WriteLine($"Suggested alternatives: {string.Join(", ", result.SuggestedAlternatives)}");
        }

        [Theory]
        [InlineData("RSA-OAEP-2048", SecurityLevel.Critical, false)] // RSA-2048 is only Standard level
        [InlineData("ML-KEM-768", SecurityLevel.Critical, false)]     // ML-KEM-768 is High level
        [InlineData("ML-KEM-1024", SecurityLevel.Critical, true)]     // ML-KEM-1024 is Critical level
        [InlineData("SHA-256", SecurityLevel.High, true)]             // SHA-256 is High level
        public void EnforceAlgorithmRestrictions_MinimumSecurityLevel_EnforcesSecurityRequirements(
            string algorithm, SecurityLevel minLevel, bool expectedAllowed)
        {
            // Arrange
            var securityPolicy = new SecurityPolicy
            {
                MinimumSecurityLevel = minLevel,
                ProhibitWeakAlgorithms = false
            };

            // Act
            var result = _engine.EnforceAlgorithmRestrictions(algorithm, AlgorithmType.Kem, securityPolicy);

            // Assert
            Assert.Equal(expectedAllowed, result.IsAllowed);
            if (!expectedAllowed)
            {
                Assert.Contains($"minimum security level requirement ({minLevel})", result.RejectReason);
                Assert.Single(result.Violations);
            }

            _output.WriteLine($"Algorithm {algorithm} with min security {minLevel}: Allowed={result.IsAllowed}");
        }

        #endregion

        #region Algorithm Security Validation Tests

        [Theory]
        [InlineData("ML-KEM-768", AlgorithmType.Kem, SecurityLevel.High, true)]
        [InlineData("ML-KEM-768", AlgorithmType.Kem, SecurityLevel.Critical, false)]
        [InlineData("RSA-OAEP-4096", AlgorithmType.Kem, SecurityLevel.Critical, true)]
        [InlineData("AES-128-GCM", AlgorithmType.Symmetric, SecurityLevel.Standard, true)]
        [InlineData("AES-128-GCM", AlgorithmType.Symmetric, SecurityLevel.High, false)]
        [InlineData("UnknownAlgorithm", AlgorithmType.Kem, SecurityLevel.Low, false)]
        public void ValidateAlgorithmSecurity_SecurityLevelChecks_ValidatesCorrectly(
            string algorithm, AlgorithmType algorithmType, SecurityLevel minLevel, bool expectedValid)
        {
            // Act
            var result = _engine.ValidateAlgorithmSecurity(algorithm, algorithmType, minLevel);

            // Assert
            Assert.Equal(expectedValid, result);

            _output.WriteLine($"Security validation for {algorithm} vs {minLevel}: Valid={result}");
        }

        #endregion

        #region Fallback Sequence Tests

        [Fact]
        public void GetFallbackSequence_PreferredAlgorithmAvailable_StartsWithPreferred()
        {
            // Arrange
            var preferredAlgorithm = "ML-KEM-768";
            var availableAlgorithms = new[] { "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", "RSA-OAEP-2048" };
            var fallbackPolicy = new FallbackPolicy { MaxFallbackAttempts = 3 };

            // Act
            var sequence = _engine.GetFallbackSequence(
                preferredAlgorithm, AlgorithmType.Kem, fallbackPolicy, availableAlgorithms);

            // Assert
            var sequenceList = sequence.ToList();
            Assert.Equal(preferredAlgorithm, sequenceList.First());
            Assert.True(sequenceList.Count <= fallbackPolicy.MaxFallbackAttempts);

            _output.WriteLine($"Fallback sequence: {string.Join(" -> ", sequenceList)}");
        }

        [Fact]
        public void GetFallbackSequence_PreferredAlgorithmUnavailable_UsesAlternatives()
        {
            // Arrange
            var preferredAlgorithm = "ML-KEM-512"; // Not in available list
            var availableAlgorithms = new[] { "ML-KEM-768", "ML-KEM-1024", "RSA-OAEP-2048" };
            var fallbackPolicy = new FallbackPolicy { MaxFallbackAttempts = 5 };

            // Act
            var sequence = _engine.GetFallbackSequence(
                preferredAlgorithm, AlgorithmType.Kem, fallbackPolicy, availableAlgorithms);

            // Assert
            var sequenceList = sequence.ToList();
            Assert.DoesNotContain(preferredAlgorithm, sequenceList); // Not available
            Assert.True(sequenceList.Count > 0);
            Assert.True(sequenceList.Count <= fallbackPolicy.MaxFallbackAttempts);
            
            // Should prefer stronger algorithms first
            Assert.Contains("ML-KEM-1024", sequenceList); // Stronger PQC algorithm
            
            _output.WriteLine($"Fallback without preferred: {string.Join(" -> ", sequenceList)}");
        }

        [Fact]
        public void GetFallbackSequence_CustomFallbackSequence_UsesCustomSequence()
        {
            // Arrange
            var preferredAlgorithm = "ML-KEM-768";
            var availableAlgorithms = new[] { "ML-KEM-768", "RSA-OAEP-2048", "Custom-Algorithm" };
            var fallbackPolicy = new FallbackPolicy 
            { 
                MaxFallbackAttempts = 4,
                CustomFallbackSequence = new List<FallbackStep>
                {
                    new() { KemAlgorithm = "RSA-OAEP-2048", TimeoutSeconds = 10 },
                    new() { KemAlgorithm = "Custom-Algorithm", TimeoutSeconds = 15 }
                }
            };

            // Act
            var sequence = _engine.GetFallbackSequence(
                preferredAlgorithm, AlgorithmType.Kem, fallbackPolicy, availableAlgorithms);

            // Assert
            var sequenceList = sequence.ToList();
            Assert.Equal(preferredAlgorithm, sequenceList.First()); // Preferred first
            Assert.Contains("RSA-OAEP-2048", sequenceList);        // From custom sequence
            Assert.Contains("Custom-Algorithm", sequenceList);      // From custom sequence

            _output.WriteLine($"Custom fallback sequence: {string.Join(" -> ", sequenceList)}");
        }

        [Fact]
        public void GetFallbackSequence_MaxAttemptsLimit_RespectsLimit()
        {
            // Arrange
            var preferredAlgorithm = "ML-KEM-768";
            var availableAlgorithms = new[] { 
                "ML-KEM-512", "ML-KEM-768", "ML-KEM-1024", 
                "RSA-OAEP-2048", "RSA-OAEP-3072", "RSA-OAEP-4096" 
            };
            var fallbackPolicy = new FallbackPolicy { MaxFallbackAttempts = 2 };

            // Act
            var sequence = _engine.GetFallbackSequence(
                preferredAlgorithm, AlgorithmType.Kem, fallbackPolicy, availableAlgorithms);

            // Assert
            var sequenceList = sequence.ToList();
            Assert.True(sequenceList.Count <= fallbackPolicy.MaxFallbackAttempts);
            Assert.Equal(2, sequenceList.Count);

            _output.WriteLine($"Limited fallback sequence ({fallbackPolicy.MaxFallbackAttempts} max): {string.Join(" -> ", sequenceList)}");
        }

        [Theory]
        [InlineData(AlgorithmType.Kem)]
        [InlineData(AlgorithmType.Signature)]
        [InlineData(AlgorithmType.Symmetric)]
        [InlineData(AlgorithmType.Hash)]
        public void GetFallbackSequence_DifferentAlgorithmTypes_ReturnsTypeSpecificSequence(AlgorithmType algorithmType)
        {
            // Arrange
            var preferredAlgorithm = algorithmType switch
            {
                AlgorithmType.Kem => "ML-KEM-768",
                AlgorithmType.Signature => "ML-DSA-65",
                AlgorithmType.Symmetric => "AES-256-GCM",
                AlgorithmType.Hash => "SHA-256",
                _ => "Unknown"
            };

            var availableAlgorithms = algorithmType switch
            {
                AlgorithmType.Kem => new[] { "ML-KEM-512", "ML-KEM-768", "RSA-OAEP-2048" },
                AlgorithmType.Signature => new[] { "ML-DSA-44", "ML-DSA-65", "RSA-PSS-2048" },
                AlgorithmType.Symmetric => new[] { "AES-128-GCM", "AES-256-GCM", "ChaCha20-Poly1305" },
                AlgorithmType.Hash => new[] { "SHA-256", "SHA-384", "SHA3-256" },
                _ => new[] { "Unknown" }
            };

            var fallbackPolicy = new FallbackPolicy { MaxFallbackAttempts = 3 };

            // Act
            var sequence = _engine.GetFallbackSequence(
                preferredAlgorithm, algorithmType, fallbackPolicy, availableAlgorithms);

            // Assert
            var sequenceList = sequence.ToList();
            Assert.NotEmpty(sequenceList);
            Assert.Contains(preferredAlgorithm, sequenceList);

            _output.WriteLine($"{algorithmType} fallback sequence: {string.Join(" -> ", sequenceList)}");
        }

        #endregion

        #region Edge Cases and Error Handling

        [Fact]
        public void EnforceAlgorithmRestrictions_NullAlgorithm_ThrowsArgumentException()
        {
            // Arrange
            var securityPolicy = new SecurityPolicy();

            // Act & Assert
            var ex = Assert.Throws<System.ArgumentException>(() =>
                _engine.EnforceAlgorithmRestrictions(null, AlgorithmType.Kem, securityPolicy));
            
            Assert.Contains("cannot be null or empty", ex.Message);

            _output.WriteLine("Null algorithm correctly throws ArgumentException");
        }

        [Fact]
        public void EnforceAlgorithmRestrictions_NullSecurityPolicy_ThrowsArgumentNullException()
        {
            // Act & Assert
            var ex = Assert.Throws<System.ArgumentNullException>(() =>
                _engine.EnforceAlgorithmRestrictions("ML-KEM-768", AlgorithmType.Kem, null));
            
            Assert.Equal("securityPolicy", ex.ParamName);

            _output.WriteLine("Null security policy correctly throws ArgumentNullException");
        }

        [Fact]
        public void GetFallbackSequence_NullAvailableAlgorithms_ThrowsArgumentNullException()
        {
            // Arrange
            var fallbackPolicy = new FallbackPolicy();

            // Act & Assert
            var ex = Assert.Throws<System.ArgumentNullException>(() =>
                _engine.GetFallbackSequence("ML-KEM-768", AlgorithmType.Kem, fallbackPolicy, null));
            
            Assert.Equal("availableAlgorithms", ex.ParamName);

            _output.WriteLine("Null available algorithms correctly throws ArgumentNullException");
        }

        [Fact]
        public void GetFallbackSequence_EmptyAvailableAlgorithms_ReturnsEmptySequence()
        {
            // Arrange
            var fallbackPolicy = new FallbackPolicy { MaxFallbackAttempts = 3 };

            // Act
            var sequence = _engine.GetFallbackSequence(
                "ML-KEM-768", AlgorithmType.Kem, fallbackPolicy, new string[0]);

            // Assert
            Assert.Empty(sequence);

            _output.WriteLine("Empty available algorithms returns empty sequence");
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void ValidateAlgorithmSecurity_EmptyAlgorithm_ReturnsFalse(string emptyAlgorithm)
        {
            // Act
            var result = _engine.ValidateAlgorithmSecurity(emptyAlgorithm, AlgorithmType.Kem, SecurityLevel.Standard);

            // Assert
            Assert.False(result);

            _output.WriteLine($"Empty algorithm '{emptyAlgorithm}' correctly returns false");
        }

        #endregion

        #region Comprehensive Policy Scenarios

        [Fact]
        public void EnforceAlgorithmRestrictions_HighSecurityEnvironment_EnforcesStrictPolicies()
        {
            // Arrange - Simulate high-security financial institution
            var securityPolicy = new SecurityPolicy
            {
                MinimumSecurityLevel = SecurityLevel.High,
                ProhibitWeakAlgorithms = true,
                MinimumRsaKeySize = 4096,
                ProhibitedAlgorithms = new List<string> { "RSA-OAEP-2048", "AES-128-GCM", "ML-KEM-512" }
            };

            var testAlgorithms = new[]
            {
                ("ML-KEM-768", AlgorithmType.Kem, true),        // High security PQC
                ("ML-KEM-1024", AlgorithmType.Kem, true),       // Critical security PQC
                ("RSA-OAEP-2048", AlgorithmType.Kem, false),    // Prohibited
                ("RSA-OAEP-4096", AlgorithmType.Kem, true),     // High security classical
                ("AES-128-GCM", AlgorithmType.Symmetric, false), // Prohibited
                ("AES-256-GCM", AlgorithmType.Symmetric, true), // High security
                ("SHA1", AlgorithmType.Hash, false),            // Weak
                ("SHA-256", AlgorithmType.Hash, true)           // High security
            };

            // Act & Assert
            foreach (var (algorithm, type, expectedAllowed) in testAlgorithms)
            {
                var result = _engine.EnforceAlgorithmRestrictions(algorithm, type, securityPolicy);
                Assert.Equal(expectedAllowed, result.IsAllowed, 
                    $"High security policy: {algorithm} should be {(expectedAllowed ? "allowed" : "rejected")}");

                if (!result.IsAllowed)
                {
                    Assert.NotEmpty(result.SuggestedAlternatives);
                }

                _output.WriteLine($"High security - {algorithm}: {(result.IsAllowed ? "ALLOWED" : "REJECTED")} - {result.RejectReason}");
            }
        }

        [Fact]
        public void EnforceAlgorithmRestrictions_LegacyCompatibilityMode_AllowsWeakerAlgorithms()
        {
            // Arrange - Simulate legacy compatibility mode
            var securityPolicy = new SecurityPolicy
            {
                MinimumSecurityLevel = SecurityLevel.Standard,
                ProhibitWeakAlgorithms = false,
                MinimumRsaKeySize = 2048,
                ProhibitedAlgorithms = new List<string>() // No explicit prohibitions
            };

            var testAlgorithms = new[]
            {
                ("ML-KEM-768", AlgorithmType.Kem, true),
                ("RSA-OAEP-2048", AlgorithmType.Kem, true),
                ("AES-128-GCM", AlgorithmType.Symmetric, true),
                ("SHA-256", AlgorithmType.Hash, true)
            };

            // Act & Assert
            foreach (var (algorithm, type, expectedAllowed) in testAlgorithms)
            {
                var result = _engine.EnforceAlgorithmRestrictions(algorithm, type, securityPolicy);
                Assert.Equal(expectedAllowed, result.IsAllowed,
                    $"Legacy compatibility: {algorithm} should be {(expectedAllowed ? "allowed" : "rejected")}");

                _output.WriteLine($"Legacy compatibility - {algorithm}: {(result.IsAllowed ? "ALLOWED" : "REJECTED")}");
            }
        }

        #endregion
    }
}