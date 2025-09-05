using System;
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
    public class AlgorithmSelectorTests
    {
        private AlgorithmSelector _selector;
        private Mock<ICryptographicProvider> _mockProvider;
        private Mock<ILogger<AlgorithmSelector>> _mockLogger;
        private AlgorithmConfiguration _hybridConfig;
        private AlgorithmConfiguration _pqcOnlyConfig;
        private AlgorithmConfiguration _classicalOnlyConfig;

        [SetUp]
        public void SetUp()
        {
            _mockProvider = new Mock<ICryptographicProvider>();
            _mockLogger = new Mock<ILogger<AlgorithmSelector>>();
            
            _hybridConfig = AlgorithmConfiguration.CreateDefault();
            _pqcOnlyConfig = AlgorithmConfiguration.CreatePostQuantumOnly();
            _classicalOnlyConfig = AlgorithmConfiguration.CreateClassicalOnly();

            _mockProvider.Setup(p => p.IsAlgorithmSupported(It.IsAny<string>())).Returns(true);

            _selector = new AlgorithmSelector(_hybridConfig, _mockProvider.Object, _mockLogger.Object);
        }

        #region Constructor Tests

        [Test]
        public void Constructor_WithNullConfiguration_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new AlgorithmSelector(null, _mockProvider.Object, _mockLogger.Object));
        }

        [Test]
        public void Constructor_WithNullProvider_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new AlgorithmSelector(_hybridConfig, null, _mockLogger.Object));
        }

        [Test]
        public void Constructor_WithNullLogger_ShouldThrowArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => 
                new AlgorithmSelector(_hybridConfig, _mockProvider.Object, null));
        }

        #endregion

        #region KEM Algorithm Selection Tests

        [Test]
        public void SelectKemAlgorithm_WithHybridMode_ShouldReturnHybridSelection()
        {
            // Arrange
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: true
            );

            // Act
            var result = _selector.SelectKemAlgorithm(capabilities);

            // Assert
            result.Should().NotBeNull();
            result.Primary.Should().Be("ML-KEM-768");
            result.Fallback.Should().Be("RSA-OAEP-2048");
            result.IsHybrid.Should().BeTrue();
        }

        [Test]
        public void SelectKemAlgorithm_WithPqcOnlyMode_ShouldReturnPqcSelection()
        {
            // Arrange
            var selector = new AlgorithmSelector(_pqcOnlyConfig, _mockProvider.Object, _mockLogger.Object);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768", "ML-KEM-1024" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: false
            );

            // Act
            var result = selector.SelectKemAlgorithm(capabilities);

            // Assert
            result.Should().NotBeNull();
            result.Primary.Should().Be("ML-KEM-768");
            result.Fallback.Should().Be("ML-KEM-1024"); // Stronger PQC fallback
            result.IsHybrid.Should().BeFalse();
        }

        [Test]
        public void SelectKemAlgorithm_WithClassicalOnlyMode_ShouldReturnClassicalSelection()
        {
            // Arrange
            var selector = new AlgorithmSelector(_classicalOnlyConfig, _mockProvider.Object, _mockLogger.Object);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: false,
                supportedPqcKemAlgorithms: new string[0],
                supportedPqcSignatureAlgorithms: new string[0],
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048", "RSA-OAEP-4096" },
                supportsHybrid: false
            );

            // Act
            var result = selector.SelectKemAlgorithm(capabilities);

            // Assert
            result.Should().NotBeNull();
            result.Primary.Should().Be("RSA-OAEP-4096"); // Stronger classical algorithm
            result.Fallback.Should().Be("RSA-OAEP-2048");
            result.IsHybrid.Should().BeFalse();
        }

        [Test]
        public void SelectKemAlgorithm_WithPerformanceRequirements_ShouldPreferFasterAlgorithm()
        {
            // Arrange
            var selector = new AlgorithmSelector(_classicalOnlyConfig, _mockProvider.Object, _mockLogger.Object);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: false,
                supportedPqcKemAlgorithms: new string[0],
                supportedPqcSignatureAlgorithms: new string[0],
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048", "RSA-OAEP-4096" },
                supportsHybrid: false
            );
            var performanceReqs = new PerformanceRequirements { RequireFastOperation = true };

            // Act
            var result = selector.SelectKemAlgorithm(capabilities, performanceReqs);

            // Assert
            result.Should().NotBeNull();
            result.Primary.Should().Be("RSA-OAEP-2048"); // Faster algorithm preferred
        }

        [Test]
        public void SelectKemAlgorithm_WithLimitedRecipientSupport_ShouldSelectSupportedAlgorithm()
        {
            // Arrange
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-1024" }, // Only supports stronger variant
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-4096" },
                supportsHybrid: true
            );

            // Act
            var result = _selector.SelectKemAlgorithm(capabilities);

            // Assert
            result.Should().NotBeNull();
            result.Primary.Should().Be("ML-KEM-1024"); // Uses what recipient supports
            result.Fallback.Should().Be("RSA-OAEP-4096");
            result.IsHybrid.Should().BeTrue();
        }

        #endregion

        #region Signature Algorithm Selection Tests

        [Test]
        public void SelectSignatureAlgorithm_WithHybridMode_ShouldReturnHybridSelection()
        {
            // Arrange
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-PSS-2048" },
                supportsHybrid: true
            );

            // Act
            var result = _selector.SelectSignatureAlgorithm(capabilities);

            // Assert
            result.Should().NotBeNull();
            result.Primary.Should().Be("ML-DSA-65");
            result.Fallback.Should().Be("RSA-PSS-2048");
            result.IsHybrid.Should().BeTrue();
        }

        [Test]
        public void SelectSignatureAlgorithm_WithPqcOnlyMode_ShouldReturnPqcSelection()
        {
            // Arrange
            var selector = new AlgorithmSelector(_pqcOnlyConfig, _mockProvider.Object, _mockLogger.Object);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65", "ML-DSA-87" },
                supportedClassicalAlgorithms: new[] { "RSA-PSS-2048" },
                supportsHybrid: false
            );

            // Act
            var result = selector.SelectSignatureAlgorithm(capabilities);

            // Assert
            result.Should().NotBeNull();
            result.Primary.Should().Be("ML-DSA-65");
            result.Fallback.Should().Be("ML-DSA-87"); // Stronger PQC fallback
            result.IsHybrid.Should().BeFalse();
        }

        [Test]
        public void SelectSignatureAlgorithm_WithClassicalOnlyMode_ShouldReturnClassicalSelection()
        {
            // Arrange
            var selector = new AlgorithmSelector(_classicalOnlyConfig, _mockProvider.Object, _mockLogger.Object);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: false,
                supportedPqcKemAlgorithms: new string[0],
                supportedPqcSignatureAlgorithms: new string[0],
                supportedClassicalAlgorithms: new[] { "RSA-PSS-2048", "RSA-PSS-4096" },
                supportsHybrid: false
            );

            // Act
            var result = selector.SelectSignatureAlgorithm(capabilities);

            // Assert
            result.Should().NotBeNull();
            result.Primary.Should().Be("RSA-PSS-4096"); // Stronger classical algorithm
            result.Fallback.Should().Be("RSA-PSS-2048");
            result.IsHybrid.Should().BeFalse();
        }

        #endregion

        #region Strategy Recommendation Tests

        [Test]
        public void RecommendEncryptionStrategy_WithNullCapabilities_ShouldReturnClassicalWithLowConfidence()
        {
            // Act
            var recommendation = _selector.RecommendEncryptionStrategy(null);

            // Assert
            recommendation.Should().NotBeNull();
            recommendation.Strategy.Should().Be(EncryptionStrategy.ClassicalOnly);
            recommendation.ConfidenceScore.Should().Be(0.5f);
            recommendation.Reasoning.Should().Contain("Unknown recipient capabilities");
        }

        [Test]
        public void RecommendEncryptionStrategy_WithHybridCapableRecipient_ShouldRecommendHybrid()
        {
            // Arrange
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: true
            );

            // Act
            var recommendation = _selector.RecommendEncryptionStrategy(capabilities);

            // Assert
            recommendation.Should().NotBeNull();
            recommendation.Strategy.Should().Be(EncryptionStrategy.Hybrid);
            recommendation.ConfidenceScore.Should().Be(0.95f);
            recommendation.Reasoning.Should().Contain("explicitly supports hybrid");
        }

        [Test]
        public void RecommendEncryptionStrategy_WithPqcOnlyMode_ShouldRecommendPqcOnly()
        {
            // Arrange
            var selector = new AlgorithmSelector(_pqcOnlyConfig, _mockProvider.Object, _mockLogger.Object);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: false
            );

            // Act
            var recommendation = selector.RecommendEncryptionStrategy(capabilities);

            // Assert
            recommendation.Should().NotBeNull();
            recommendation.Strategy.Should().Be(EncryptionStrategy.PostQuantumOnly);
            recommendation.ConfidenceScore.Should().Be(0.95f);
            recommendation.Reasoning.Should().Contain("supports preferred PQC algorithms");
        }

        [Test]
        public void RecommendEncryptionStrategy_WithClassicalOnlyMode_ShouldRecommendClassicalOnly()
        {
            // Arrange
            var selector = new AlgorithmSelector(_classicalOnlyConfig, _mockProvider.Object, _mockLogger.Object);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: true,
                supportedPqcKemAlgorithms: new[] { "ML-KEM-768" },
                supportedPqcSignatureAlgorithms: new[] { "ML-DSA-65" },
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: true
            );

            // Act
            var recommendation = selector.RecommendEncryptionStrategy(capabilities);

            // Assert
            recommendation.Should().NotBeNull();
            recommendation.Strategy.Should().Be(EncryptionStrategy.ClassicalOnly);
            recommendation.ConfidenceScore.Should().Be(1.0f);
            recommendation.Reasoning.Should().Contain("Configured for classical only");
        }

        [Test]
        public void RecommendEncryptionStrategy_WithPqcButNotHybridSupport_ShouldRecommendPqcOnly()
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
            var recommendation = _selector.RecommendEncryptionStrategy(capabilities);

            // Assert
            recommendation.Should().NotBeNull();
            recommendation.Strategy.Should().Be(EncryptionStrategy.PostQuantumOnly);
            recommendation.ConfidenceScore.Should().Be(0.75f);
            recommendation.Reasoning.Should().Contain("supports PQC, use PQC-only");
        }

        [Test]
        public void RecommendEncryptionStrategy_WithNoCompatibleAlgorithms_ShouldRecommendClassicalFallback()
        {
            // Arrange
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: false,
                supportedPqcKemAlgorithms: new string[0],
                supportedPqcSignatureAlgorithms: new string[0],
                supportedClassicalAlgorithms: new[] { "RSA-OAEP-2048" },
                supportsHybrid: false
            );

            // Act
            var recommendation = _selector.RecommendEncryptionStrategy(capabilities);

            // Assert
            recommendation.Should().NotBeNull();
            recommendation.Strategy.Should().Be(EncryptionStrategy.ClassicalOnly);
            recommendation.ConfidenceScore.Should().Be(0.6f);
            recommendation.Reasoning.Should().Contain("Fallback to classical algorithms");
        }

        #endregion

        #region Degradation Tests

        [Test]
        public void ShouldDegrade_WithUnsupportedAlgorithm_ShouldReturnTrue()
        {
            // Arrange
            _mockProvider.Setup(p => p.IsAlgorithmSupported("UNSUPPORTED-ALGO")).Returns(false);

            // Act
            var shouldDegrade = _selector.ShouldDegrade("UNSUPPORTED-ALGO");

            // Assert
            shouldDegrade.Should().BeTrue();
        }

        [Test]
        public void ShouldDegrade_WithSlowPerformance_ShouldReturnTrue()
        {
            // Arrange
            var slowMetrics = new PerformanceMetrics(
                operation: "Encrypt",
                algorithm: "ML-KEM-768",
                duration: TimeSpan.FromSeconds(3), // Above 2-second threshold
                inputSize: 1000,
                outputSize: 1200,
                timestamp: DateTime.UtcNow
            );

            _mockProvider.Setup(p => p.IsAlgorithmSupported("ML-KEM-768")).Returns(true);
            _mockProvider.Setup(p => p.GetLastOperationMetrics()).Returns(slowMetrics);

            // Act
            var shouldDegrade = _selector.ShouldDegrade("ML-KEM-768");

            // Assert
            shouldDegrade.Should().BeTrue();
        }

        [Test]
        public void ShouldDegrade_WithGoodPerformance_ShouldReturnFalse()
        {
            // Arrange
            var goodMetrics = new PerformanceMetrics(
                operation: "Encrypt",
                algorithm: "ML-KEM-768",
                duration: TimeSpan.FromMilliseconds(500), // Well under threshold
                inputSize: 1000,
                outputSize: 1200,
                timestamp: DateTime.UtcNow
            );

            _mockProvider.Setup(p => p.IsAlgorithmSupported("ML-KEM-768")).Returns(true);
            _mockProvider.Setup(p => p.GetLastOperationMetrics()).Returns(goodMetrics);

            // Act
            var shouldDegrade = _selector.ShouldDegrade("ML-KEM-768");

            // Assert
            shouldDegrade.Should().BeFalse();
        }

        [Test]
        public void ShouldDegrade_WithNoMetrics_ShouldReturnFalse()
        {
            // Arrange
            _mockProvider.Setup(p => p.IsAlgorithmSupported("ML-KEM-768")).Returns(true);
            _mockProvider.Setup(p => p.GetLastOperationMetrics()).Returns((PerformanceMetrics?)null);

            // Act
            var shouldDegrade = _selector.ShouldDegrade("ML-KEM-768");

            // Assert
            shouldDegrade.Should().BeFalse();
        }

        #endregion

        #region Edge Cases and Error Handling Tests

        [Test]
        public void SelectKemAlgorithm_WithNoSupportedAlgorithms_ShouldLogWarning()
        {
            // Arrange
            _mockProvider.Setup(p => p.IsAlgorithmSupported(It.IsAny<string>())).Returns(false);
            var capabilities = new RecipientCapabilities(
                supportsPostQuantum: false,
                supportedPqcKemAlgorithms: new string[0],
                supportedPqcSignatureAlgorithms: new string[0],
                supportedClassicalAlgorithms: new string[0],
                supportsHybrid: false
            );

            // Act
            var result = _selector.SelectKemAlgorithm(capabilities);

            // Assert
            result.Should().NotBeNull();
            // Verify that warnings were logged for unsupported algorithms
            _mockLogger.Verify(
                x => x.Log(
                    LogLevel.Warning,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString().Contains("not supported")),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception, string>>()),
                Times.AtLeastOnce);
        }

        [Test]
        public void StrategyRecommendation_ConfidenceScore_ShouldBeClampedBetweenZeroAndOne()
        {
            // Arrange & Act
            var lowRecommendation = new StrategyRecommendation(EncryptionStrategy.ClassicalOnly, -0.5f, "Test");
            var highRecommendation = new StrategyRecommendation(EncryptionStrategy.Hybrid, 1.5f, "Test");

            // Assert
            lowRecommendation.ConfidenceScore.Should().Be(0.0f);
            highRecommendation.ConfidenceScore.Should().Be(1.0f);
        }

        [Test]
        public void PerformanceRequirements_DefaultValues_ShouldMatchSpecifications()
        {
            // Arrange & Act
            var requirements = new PerformanceRequirements();

            // Assert
            requirements.MaxOperationTimeSeconds.Should().Be(2.0); // Per PRD requirements
            requirements.MaxMemoryUsageBytes.Should().Be(100 * 1024 * 1024); // 100MB
            requirements.RequireConstantTime.Should().BeTrue(); // Security requirement
        }

        #endregion
    }
}