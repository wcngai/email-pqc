using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using Moq;
using PqcEmail.Core.Models;
using PqcEmail.Core.Policies.Engines;
using Xunit;
using Xunit.Abstractions;

namespace PqcEmail.Core.Tests.Policies
{
    /// <summary>
    /// Comprehensive tests for the DomainRuleEngine covering pattern matching, priority handling, and policy enforcement.
    /// </summary>
    public class DomainRuleEngineTests
    {
        private readonly ITestOutputHelper _output;
        private readonly Mock<ILogger<DomainRuleEngine>> _loggerMock;
        private readonly DomainRuleEngine _engine;

        public DomainRuleEngineTests(ITestOutputHelper output)
        {
            _output = output;
            _loggerMock = new Mock<ILogger<DomainRuleEngine>>();
            _engine = new DomainRuleEngine(_loggerMock.Object);
        }

        #region Domain Rule Evaluation Tests

        [Theory]
        [InlineData("user@example.com", "*.example.com", true)]
        [InlineData("user@test.example.com", "*.example.com", true)]
        [InlineData("user@example.org", "*.example.com", false)]
        [InlineData("user@bank.internal", "*.internal", true)]
        [InlineData("admin@finance.corp.com", "finance.*", true)]
        [InlineData("user@hr.finance.corp.com", "finance.*", false)]
        [InlineData("exact@domain.com", "domain.com", true)]
        [InlineData("user@subdomain.com", "domain.com", false)]
        public void EvaluateDomainRules_WildcardPatterns_MatchesCorrectly(string email, string pattern, bool shouldMatch)
        {
            // Arrange
            var domainPolicy = new DomainPolicy
            {
                ForcePqcDomains = new List<DomainRule>
                {
                    new() { Pattern = pattern, Enabled = true, Priority = 100 }
                }
            };

            // Act
            var result = _engine.EvaluateDomainRules(email, domainPolicy);

            // Assert
            if (shouldMatch)
            {
                Assert.True(result.RequiresPqc, $"Email {email} should match pattern {pattern}");
                Assert.Single(result.MatchedRules);
                Assert.Equal(pattern, result.MatchedRules.First().Pattern);
            }
            else
            {
                Assert.False(result.RequiresPqc, $"Email {email} should not match pattern {pattern}");
                Assert.Empty(result.MatchedRules);
            }

            _output.WriteLine($"Pattern '{pattern}' vs Email '{email}': Match={shouldMatch}, Result={result.RequiresPqc}");
        }

        [Fact]
        public void EvaluateDomainRules_MultipleForcePqcRules_RequiresPqcWhenMatched()
        {
            // Arrange
            var domainPolicy = new DomainPolicy
            {
                ForcePqcDomains = new List<DomainRule>
                {
                    new() { Pattern = "*.bank.com", Enabled = true, Priority = 200 },
                    new() { Pattern = "*.financial.org", Enabled = true, Priority = 150 },
                    new() { Pattern = "secure.*", Enabled = true, Priority = 100 }
                }
            };

            // Act & Assert
            var result1 = _engine.EvaluateDomainRules("user@test.bank.com", domainPolicy);
            Assert.True(result1.RequiresPqc);
            Assert.True(result1.RequiresEncryption);
            
            var result2 = _engine.EvaluateDomainRules("admin@secure.internal", domainPolicy);
            Assert.True(result2.RequiresPqc);
            Assert.True(result2.RequiresEncryption);
            
            var result3 = _engine.EvaluateDomainRules("user@normal.company.com", domainPolicy);
            Assert.False(result3.RequiresPqc);

            _output.WriteLine($"Test bank.com: RequiresPqc={result1.RequiresPqc}");
            _output.WriteLine($"Test secure.internal: RequiresPqc={result2.RequiresPqc}");
            _output.WriteLine($"Test normal.company.com: RequiresPqc={result3.RequiresPqc}");
        }

        [Fact]
        public void EvaluateDomainRules_ProhibitUnencryptedRules_RequiresEncryptionWhenMatched()
        {
            // Arrange
            var domainPolicy = new DomainPolicy
            {
                ProhibitUnencryptedDomains = new List<DomainRule>
                {
                    new() { Pattern = "*.internal.corp", Enabled = true, Priority = 100 },
                    new() { Pattern = "hr.company.com", Enabled = true, Priority = 150 }
                }
            };

            // Act & Assert
            var result1 = _engine.EvaluateDomainRules("user@hr.company.com", domainPolicy);
            Assert.True(result1.RequiresEncryption);
            Assert.False(result1.RequiresPqc); // Not force PQC, just require encryption
            
            var result2 = _engine.EvaluateDomainRules("admin@dept.internal.corp", domainPolicy);
            Assert.True(result2.RequiresEncryption);
            
            var result3 = _engine.EvaluateDomainRules("user@external.com", domainPolicy);
            Assert.False(result3.RequiresEncryption);

            _output.WriteLine($"HR domain requires encryption: {result1.RequiresEncryption}");
            _output.WriteLine($"Internal corp requires encryption: {result2.RequiresEncryption}");
            _output.WriteLine($"External domain requires encryption: {result3.RequiresEncryption}");
        }

        [Fact]
        public void EvaluateDomainRules_AllowClassicalOnlyRules_AllowsClassicalWhenMatched()
        {
            // Arrange
            var domainPolicy = new DomainPolicy
            {
                AllowClassicalOnlyDomains = new List<DomainRule>
                {
                    new() { Pattern = "*.legacy.system", Enabled = true, Priority = 100 },
                    new() { Pattern = "old.partner.com", Enabled = true, Priority = 150 }
                }
            };

            // Act & Assert
            var result1 = _engine.EvaluateDomainRules("user@app.legacy.system", domainPolicy);
            Assert.True(result1.AllowsClassicalOnly);
            
            var result2 = _engine.EvaluateDomainRules("contact@old.partner.com", domainPolicy);
            Assert.True(result2.AllowsClassicalOnly);
            
            var result3 = _engine.EvaluateDomainRules("user@modern.company.com", domainPolicy);
            Assert.False(result3.AllowsClassicalOnly);

            _output.WriteLine($"Legacy system allows classical: {result1.AllowsClassicalOnly}");
            _output.WriteLine($"Old partner allows classical: {result2.AllowsClassicalOnly}");
            _output.WriteLine($"Modern company allows classical: {result3.AllowsClassicalOnly}");
        }

        [Fact]
        public void EvaluateDomainRules_ConflictingRules_ForcePqcOverridesClassicalOnly()
        {
            // Arrange - Create conflicting rules where both PQC and classical-only match the same domain
            var domainPolicy = new DomainPolicy
            {
                ForcePqcDomains = new List<DomainRule>
                {
                    new() { Pattern = "*.conflicted.com", Enabled = true, Priority = 200 }
                },
                AllowClassicalOnlyDomains = new List<DomainRule>
                {
                    new() { Pattern = "*.conflicted.com", Enabled = true, Priority = 100 }
                }
            };

            // Act
            var result = _engine.EvaluateDomainRules("user@test.conflicted.com", domainPolicy);

            // Assert - Force PQC should take precedence over allow classical
            Assert.True(result.RequiresPqc);
            Assert.True(result.RequiresEncryption);
            // When PQC is required, classical-only should be false regardless of the rule
            Assert.False(result.AllowsClassicalOnly);

            _output.WriteLine($"Conflicting rules resolved: RequiresPqc={result.RequiresPqc}, AllowsClassicalOnly={result.AllowsClassicalOnly}");
        }

        #endregion

        #region Rule Priority Tests

        [Fact]
        public void FindMatchingRule_MultiplePatternsMatch_ReturnsHighestPriority()
        {
            // Arrange
            var rules = new List<DomainRule>
            {
                new() { Pattern = "*.com", Enabled = true, Priority = 50 },
                new() { Pattern = "*.bank.com", Enabled = true, Priority = 200 },
                new() { Pattern = "*", Enabled = true, Priority = 10 } // Catch-all
            };

            // Act
            var result = _engine.FindMatchingRule("user@test.bank.com", rules);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("*.bank.com", result.Pattern);
            Assert.Equal(200, result.Priority);

            _output.WriteLine($"Matched rule: {result.Pattern} (Priority: {result.Priority})");
        }

        [Fact]
        public void FindMatchingRule_DisabledRules_IgnoresDisabledRules()
        {
            // Arrange
            var rules = new List<DomainRule>
            {
                new() { Pattern = "*.bank.com", Enabled = false, Priority = 200 }, // Disabled
                new() { Pattern = "*.com", Enabled = true, Priority = 100 }
            };

            // Act
            var result = _engine.FindMatchingRule("user@test.bank.com", rules);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("*.com", result.Pattern);
            Assert.Equal(100, result.Priority);

            _output.WriteLine($"Disabled rule ignored, matched: {result.Pattern}");
        }

        #endregion

        #region Domain Override Tests

        [Fact]
        public void EvaluateDomainRules_DomainSpecificOverrides_AppliesOverrides()
        {
            // Arrange
            var domainPolicy = new DomainPolicy
            {
                DomainOverrides = new Dictionary<string, DomainSpecificPolicy>
                {
                    ["special.company.com"] = new()
                    {
                        ModeOverride = CryptographicMode.PostQuantumOnly,
                        RequireEncryption = true,
                        SecurityLevelOverride = SecurityLevel.Critical
                    }
                }
            };

            // Act
            var result = _engine.EvaluateDomainRules("user@special.company.com", domainPolicy);

            // Assert
            Assert.NotNull(result.DomainOverrides);
            Assert.Equal(CryptographicMode.PostQuantumOnly, result.DomainOverrides.ModeOverride);
            Assert.True(result.DomainOverrides.RequireEncryption);
            Assert.Equal(SecurityLevel.Critical, result.DomainOverrides.SecurityLevelOverride);

            _output.WriteLine($"Domain override applied: Mode={result.DomainOverrides.ModeOverride}, RequireEncryption={result.DomainOverrides.RequireEncryption}");
        }

        [Fact]
        public void EvaluateDomainRules_WildcardDomainOverrides_AppliesMatchingOverrides()
        {
            // Arrange
            var domainPolicy = new DomainPolicy
            {
                DomainOverrides = new Dictionary<string, DomainSpecificPolicy>
                {
                    ["*.financial.org"] = new()
                    {
                        ModeOverride = CryptographicMode.Hybrid,
                        RequireEncryption = true,
                        SecurityLevelOverride = SecurityLevel.High
                    },
                    ["normal.company.com"] = new()
                    {
                        ModeOverride = CryptographicMode.ClassicalOnly
                    }
                }
            };

            // Act
            var result1 = _engine.EvaluateDomainRules("user@bank.financial.org", domainPolicy);
            var result2 = _engine.EvaluateDomainRules("admin@credit.financial.org", domainPolicy);
            var result3 = _engine.EvaluateDomainRules("user@normal.company.com", domainPolicy);
            var result4 = _engine.EvaluateDomainRules("user@other.company.com", domainPolicy);

            // Assert
            Assert.NotNull(result1.DomainOverrides);
            Assert.Equal(CryptographicMode.Hybrid, result1.DomainOverrides.ModeOverride);

            Assert.NotNull(result2.DomainOverrides);
            Assert.Equal(CryptographicMode.Hybrid, result2.DomainOverrides.ModeOverride);

            Assert.NotNull(result3.DomainOverrides);
            Assert.Equal(CryptographicMode.ClassicalOnly, result3.DomainOverrides.ModeOverride);

            Assert.Null(result4.DomainOverrides);

            _output.WriteLine($"Wildcard override applied to bank.financial.org: {result1.DomainOverrides?.ModeOverride}");
            _output.WriteLine($"Wildcard override applied to credit.financial.org: {result2.DomainOverrides?.ModeOverride}");
            _output.WriteLine($"Exact override applied to normal.company.com: {result3.DomainOverrides?.ModeOverride}");
            _output.WriteLine($"No override for other.company.com: {result4.DomainOverrides?.ModeOverride}");
        }

        #endregion

        #region Rule Validation Tests

        [Fact]
        public void ValidateDomainRules_ValidRules_ReturnsValid()
        {
            // Arrange
            var rules = new List<DomainRule>
            {
                new() { Pattern = "*.example.com", Enabled = true, Priority = 100 },
                new() { Pattern = "exact.domain.com", Enabled = true, Priority = 150 },
                new() { Pattern = "test.*", Enabled = true, Priority = 75 }
            };

            // Act
            var result = _engine.ValidateDomainRules(rules);

            // Assert
            Assert.True(result.IsValid);
            Assert.Empty(result.Errors);

            _output.WriteLine($"Validation result: IsValid={result.IsValid}, Errors={result.Errors.Count}, Warnings={result.Warnings.Count}");
        }

        [Fact]
        public void ValidateDomainRules_EmptyPattern_ReturnsInvalid()
        {
            // Arrange
            var rules = new List<DomainRule>
            {
                new() { Pattern = "", Enabled = true, Priority = 100 },
                new() { Pattern = "   ", Enabled = true, Priority = 150 }
            };

            // Act
            var result = _engine.ValidateDomainRules(rules);

            // Assert
            Assert.False(result.IsValid);
            Assert.Contains("Domain rule pattern cannot be empty", result.Errors);

            _output.WriteLine($"Empty pattern validation: Errors={string.Join(", ", result.Errors)}");
        }

        [Fact]
        public void ValidateDomainRules_DuplicatePatterns_ReturnsWarning()
        {
            // Arrange
            var rules = new List<DomainRule>
            {
                new() { Pattern = "*.example.com", Enabled = true, Priority = 100 },
                new() { Pattern = "*.example.com", Enabled = true, Priority = 150 } // Duplicate
            };

            // Act
            var result = _engine.ValidateDomainRules(rules);

            // Assert
            Assert.True(result.IsValid); // Still valid, just a warning
            Assert.Contains("Duplicate domain pattern found: *.example.com", result.Warnings);

            _output.WriteLine($"Duplicate pattern warning: Warnings={string.Join(", ", result.Warnings)}");
        }

        [Fact]
        public void ValidateDomainRules_InvalidPriority_ReturnsWarning()
        {
            // Arrange
            var rules = new List<DomainRule>
            {
                new() { Pattern = "*.example.com", Enabled = true, Priority = -50 },
                new() { Pattern = "*.test.com", Enabled = true, Priority = 2000 }
            };

            // Act
            var result = _engine.ValidateDomainRules(rules);

            // Assert
            Assert.True(result.IsValid);
            Assert.True(result.Warnings.Any(w => w.Contains("priority -50 is outside recommended range")));
            Assert.True(result.Warnings.Any(w => w.Contains("priority 2000 is outside recommended range")));

            _output.WriteLine($"Priority warnings: {string.Join(", ", result.Warnings)}");
        }

        [Theory]
        [InlineData("*.example.com")]
        [InlineData("exact.domain.com")]
        [InlineData("test.*")]
        [InlineData("*.*.example.com")]
        [InlineData("sub?.domain.com")]
        public void ValidateDomainRules_ValidPatterns_PassValidation(string pattern)
        {
            // Arrange
            var rules = new List<DomainRule>
            {
                new() { Pattern = pattern, Enabled = true, Priority = 100 }
            };

            // Act
            var result = _engine.ValidateDomainRules(rules);

            // Assert
            Assert.True(result.IsValid, $"Pattern '{pattern}' should be valid");
            Assert.Empty(result.Errors);

            _output.WriteLine($"Pattern '{pattern}' validation: Valid");
        }

        #endregion

        #region Edge Case Tests

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        [InlineData("invalid-email")]
        [InlineData("@domain.com")]
        [InlineData("user@")]
        public void EvaluateDomainRules_InvalidEmailFormats_HandlesGracefully(string invalidEmail)
        {
            // Arrange
            var domainPolicy = new DomainPolicy
            {
                ForcePqcDomains = new List<DomainRule>
                {
                    new() { Pattern = "*.example.com", Enabled = true, Priority = 100 }
                }
            };

            // Act & Assert
            if (string.IsNullOrEmpty(invalidEmail) || string.IsNullOrWhiteSpace(invalidEmail))
            {
                var ex = Assert.Throws<ArgumentException>(() => _engine.EvaluateDomainRules(invalidEmail, domainPolicy));
                Assert.Contains("Recipient email cannot be null or empty", ex.Message);
            }
            else
            {
                var result = _engine.EvaluateDomainRules(invalidEmail, domainPolicy);
                Assert.False(result.RequiresPqc);
                Assert.Empty(result.MatchedRules);
            }

            _output.WriteLine($"Invalid email '{invalidEmail}' handled gracefully");
        }

        [Fact]
        public void EvaluateDomainRules_NullDomainPolicy_ThrowsArgumentNullException()
        {
            // Act & Assert
            var ex = Assert.Throws<ArgumentNullException>(() => 
                _engine.EvaluateDomainRules("user@example.com", null));
            
            Assert.Equal("domainPolicy", ex.ParamName);

            _output.WriteLine("Null domain policy correctly throws ArgumentNullException");
        }

        [Fact]
        public void FindMatchingRule_NullOrEmptyRules_ReturnsNull()
        {
            // Act & Assert
            var result1 = _engine.FindMatchingRule("user@example.com", null);
            var result2 = _engine.FindMatchingRule("user@example.com", new List<DomainRule>());

            Assert.Null(result1);
            Assert.Null(result2);

            _output.WriteLine("Null or empty rules correctly return null");
        }

        [Fact]
        public void FindMatchingRule_CaseInsensitiveMatching_WorksCorrectly()
        {
            // Arrange
            var rules = new List<DomainRule>
            {
                new() { Pattern = "*.EXAMPLE.COM", Enabled = true, Priority = 100 }
            };

            // Act
            var result = _engine.FindMatchingRule("user@test.example.com", rules);

            // Assert
            Assert.NotNull(result);
            Assert.Equal("*.EXAMPLE.COM", result.Pattern);

            _output.WriteLine($"Case insensitive matching works: Pattern='{result.Pattern}'");
        }

        #endregion
    }
}