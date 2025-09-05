using System;
using System.Linq;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Cryptography
{
    /// <summary>
    /// Provides intelligent algorithm selection based on configuration, recipient capabilities, and runtime conditions.
    /// </summary>
    public class AlgorithmSelector
    {
        private readonly AlgorithmConfiguration _configuration;
        private readonly ICryptographicProvider _cryptographicProvider;
        private readonly ILogger<AlgorithmSelector> _logger;

        /// <summary>
        /// Initializes a new instance of the <see cref="AlgorithmSelector"/> class.
        /// </summary>
        /// <param name="configuration">The algorithm configuration</param>
        /// <param name="cryptographicProvider">The cryptographic provider</param>
        /// <param name="logger">The logger instance</param>
        public AlgorithmSelector(
            AlgorithmConfiguration configuration, 
            ICryptographicProvider cryptographicProvider,
            ILogger<AlgorithmSelector> logger)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _cryptographicProvider = cryptographicProvider ?? throw new ArgumentNullException(nameof(cryptographicProvider));
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Selects the optimal key encapsulation mechanism algorithm.
        /// </summary>
        /// <param name="recipientCapabilities">The recipient's capabilities</param>
        /// <param name="performanceRequirements">Performance requirements for the operation</param>
        /// <returns>The selected KEM algorithm and fallback options</returns>
        public AlgorithmSelectionResult SelectKemAlgorithm(
            RecipientCapabilities? recipientCapabilities = null, 
            PerformanceRequirements? performanceRequirements = null)
        {
            _logger.LogDebug("Selecting KEM algorithm with mode: {Mode}", _configuration.Mode);

            var selectionResult = new AlgorithmSelectionResult();

            switch (_configuration.Mode)
            {
                case CryptographicMode.ClassicalOnly:
                    selectionResult.Primary = SelectBestClassicalKem(recipientCapabilities, performanceRequirements);
                    selectionResult.Fallback = _configuration.FallbackKemAlgorithm;
                    break;

                case CryptographicMode.PostQuantumOnly:
                    selectionResult.Primary = SelectBestPqcKem(recipientCapabilities, performanceRequirements);
                    selectionResult.Fallback = GetStrongerPqcKemAlgorithm(_configuration.PreferredKemAlgorithm);
                    break;

                case CryptographicMode.Hybrid:
                    selectionResult = SelectHybridKemAlgorithms(recipientCapabilities, performanceRequirements);
                    break;
            }

            ValidateAlgorithmSupport(selectionResult);
            _logger.LogInformation("Selected KEM algorithm: {Primary}, Fallback: {Fallback}", 
                selectionResult.Primary, selectionResult.Fallback);

            return selectionResult;
        }

        /// <summary>
        /// Selects the optimal digital signature algorithm.
        /// </summary>
        /// <param name="recipientCapabilities">The recipient's capabilities</param>
        /// <param name="performanceRequirements">Performance requirements for the operation</param>
        /// <returns>The selected signature algorithm and fallback options</returns>
        public AlgorithmSelectionResult SelectSignatureAlgorithm(
            RecipientCapabilities? recipientCapabilities = null,
            PerformanceRequirements? performanceRequirements = null)
        {
            _logger.LogDebug("Selecting signature algorithm with mode: {Mode}", _configuration.Mode);

            var selectionResult = new AlgorithmSelectionResult();

            switch (_configuration.Mode)
            {
                case CryptographicMode.ClassicalOnly:
                    selectionResult.Primary = SelectBestClassicalSignature(recipientCapabilities, performanceRequirements);
                    selectionResult.Fallback = _configuration.FallbackSignatureAlgorithm;
                    break;

                case CryptographicMode.PostQuantumOnly:
                    selectionResult.Primary = SelectBestPqcSignature(recipientCapabilities, performanceRequirements);
                    selectionResult.Fallback = GetStrongerPqcSignatureAlgorithm(_configuration.PreferredSignatureAlgorithm);
                    break;

                case CryptographicMode.Hybrid:
                    selectionResult = SelectHybridSignatureAlgorithms(recipientCapabilities, performanceRequirements);
                    break;
            }

            ValidateAlgorithmSupport(selectionResult);
            _logger.LogInformation("Selected signature algorithm: {Primary}, Fallback: {Fallback}", 
                selectionResult.Primary, selectionResult.Fallback);

            return selectionResult;
        }

        /// <summary>
        /// Evaluates recipient capabilities and recommends the optimal encryption strategy.
        /// </summary>
        /// <param name="recipientCapabilities">The recipient's capabilities</param>
        /// <returns>The recommended encryption strategy with confidence score</returns>
        public StrategyRecommendation RecommendEncryptionStrategy(RecipientCapabilities recipientCapabilities)
        {
            if (recipientCapabilities == null)
            {
                return new StrategyRecommendation(EncryptionStrategy.ClassicalOnly, 0.5f, "Unknown recipient capabilities");
            }

            var recommendation = _configuration.Mode switch
            {
                CryptographicMode.ClassicalOnly => new StrategyRecommendation(EncryptionStrategy.ClassicalOnly, 1.0f, "Configured for classical only"),
                CryptographicMode.PostQuantumOnly => EvaluatePqcOnlyStrategy(recipientCapabilities),
                CryptographicMode.Hybrid => EvaluateHybridStrategy(recipientCapabilities),
                _ => new StrategyRecommendation(EncryptionStrategy.ClassicalOnly, 0.3f, "Unknown configuration mode")
            };

            _logger.LogInformation("Recommended encryption strategy: {Strategy} (confidence: {Confidence:P1}) - {Reason}", 
                recommendation.Strategy, recommendation.ConfidenceScore, recommendation.Reasoning);

            return recommendation;
        }

        /// <summary>
        /// Checks if graceful degradation is needed based on algorithm availability.
        /// </summary>
        /// <param name="preferredAlgorithm">The preferred algorithm</param>
        /// <returns>True if degradation is recommended, false otherwise</returns>
        public bool ShouldDegrade(string preferredAlgorithm)
        {
            if (!_cryptographicProvider.IsAlgorithmSupported(preferredAlgorithm))
            {
                _logger.LogWarning("Preferred algorithm {Algorithm} is not supported, degradation recommended", preferredAlgorithm);
                return true;
            }

            // Check performance metrics from last operations
            var metrics = _cryptographicProvider.GetLastOperationMetrics();
            if (metrics != null && metrics.Duration.TotalSeconds > 2.0) // Performance threshold from requirements
            {
                _logger.LogWarning("Algorithm {Algorithm} performance is below threshold ({Duration}s), degradation recommended", 
                    preferredAlgorithm, metrics.Duration.TotalSeconds);
                return true;
            }

            return false;
        }

        #region Private Methods

        private string SelectBestClassicalKem(RecipientCapabilities? capabilities, PerformanceRequirements? performance)
        {
            var candidates = new[] { "RSA-OAEP-2048", "RSA-OAEP-4096" };
            
            if (capabilities?.SupportedClassicalAlgorithms != null)
            {
                var supported = candidates.Where(alg => capabilities.SupportedClassicalAlgorithms.Contains(alg)).ToArray();
                if (supported.Any())
                {
                    candidates = supported;
                }
            }

            // Prefer stronger algorithms unless performance is critical
            if (performance?.RequireFastOperation == true)
            {
                return candidates.Contains("RSA-OAEP-2048") ? "RSA-OAEP-2048" : candidates.First();
            }

            return candidates.Contains("RSA-OAEP-4096") ? "RSA-OAEP-4096" : candidates.First();
        }

        private string SelectBestPqcKem(RecipientCapabilities? capabilities, PerformanceRequirements? performance)
        {
            var candidates = new[] { "ML-KEM-768", "ML-KEM-1024" };
            
            if (capabilities?.SupportedPqcKemAlgorithms != null)
            {
                var supported = candidates.Where(alg => capabilities.SupportedPqcKemAlgorithms.Contains(alg)).ToArray();
                if (supported.Any())
                {
                    candidates = supported;
                }
            }

            // ML-KEM-768 provides 192-bit security level which meets requirements
            return candidates.Contains(_configuration.PreferredKemAlgorithm) ? _configuration.PreferredKemAlgorithm : candidates.First();
        }

        private string SelectBestClassicalSignature(RecipientCapabilities? capabilities, PerformanceRequirements? performance)
        {
            var candidates = new[] { "RSA-PSS-2048", "RSA-PSS-4096" };
            
            if (capabilities?.SupportedClassicalAlgorithms != null)
            {
                var supported = candidates.Where(alg => capabilities.SupportedClassicalAlgorithms.Contains(alg)).ToArray();
                if (supported.Any())
                {
                    candidates = supported;
                }
            }

            if (performance?.RequireFastOperation == true)
            {
                return candidates.Contains("RSA-PSS-2048") ? "RSA-PSS-2048" : candidates.First();
            }

            return candidates.Contains("RSA-PSS-4096") ? "RSA-PSS-4096" : candidates.First();
        }

        private string SelectBestPqcSignature(RecipientCapabilities? capabilities, PerformanceRequirements? performance)
        {
            var candidates = new[] { "ML-DSA-65", "ML-DSA-87" };
            
            if (capabilities?.SupportedPqcSignatureAlgorithms != null)
            {
                var supported = candidates.Where(alg => capabilities.SupportedPqcSignatureAlgorithms.Contains(alg)).ToArray();
                if (supported.Any())
                {
                    candidates = supported;
                }
            }

            return candidates.Contains(_configuration.PreferredSignatureAlgorithm) ? _configuration.PreferredSignatureAlgorithm : candidates.First();
        }

        private AlgorithmSelectionResult SelectHybridKemAlgorithms(RecipientCapabilities? capabilities, PerformanceRequirements? performance)
        {
            return new AlgorithmSelectionResult
            {
                Primary = SelectBestPqcKem(capabilities, performance),
                Fallback = SelectBestClassicalKem(capabilities, performance),
                IsHybrid = true
            };
        }

        private AlgorithmSelectionResult SelectHybridSignatureAlgorithms(RecipientCapabilities? capabilities, PerformanceRequirements? performance)
        {
            return new AlgorithmSelectionResult
            {
                Primary = SelectBestPqcSignature(capabilities, performance),
                Fallback = SelectBestClassicalSignature(capabilities, performance),
                IsHybrid = true
            };
        }

        private StrategyRecommendation EvaluatePqcOnlyStrategy(RecipientCapabilities capabilities)
        {
            if (!capabilities.SupportsPostQuantum)
            {
                return new StrategyRecommendation(EncryptionStrategy.PostQuantumOnly, 0.2f, 
                    "Recipient doesn't support PQC but system configured for PQC-only");
            }

            var supportsPqcKem = capabilities.SupportedPqcKemAlgorithms.Contains(_configuration.PreferredKemAlgorithm);
            var supportsPqcSig = capabilities.SupportedPqcSignatureAlgorithms.Contains(_configuration.PreferredSignatureAlgorithm);

            if (supportsPqcKem && supportsPqcSig)
            {
                return new StrategyRecommendation(EncryptionStrategy.PostQuantumOnly, 0.95f, 
                    "Recipient supports preferred PQC algorithms");
            }
            else if (supportsPqcKem || supportsPqcSig)
            {
                return new StrategyRecommendation(EncryptionStrategy.PostQuantumOnly, 0.7f, 
                    "Recipient supports some PQC algorithms");
            }

            return new StrategyRecommendation(EncryptionStrategy.PostQuantumOnly, 0.3f, 
                "Limited PQC support from recipient");
        }

        private StrategyRecommendation EvaluateHybridStrategy(RecipientCapabilities capabilities)
        {
            if (capabilities.SupportsHybrid)
            {
                return new StrategyRecommendation(EncryptionStrategy.Hybrid, 0.95f, 
                    "Recipient explicitly supports hybrid mode");
            }

            if (capabilities.SupportsPostQuantum && capabilities.SupportedClassicalAlgorithms.Any())
            {
                return new StrategyRecommendation(EncryptionStrategy.Hybrid, 0.8f, 
                    "Recipient supports both PQC and classical algorithms");
            }

            if (capabilities.SupportsPostQuantum)
            {
                return new StrategyRecommendation(EncryptionStrategy.PostQuantumOnly, 0.75f, 
                    "Recipient supports PQC, use PQC-only");
            }

            return new StrategyRecommendation(EncryptionStrategy.ClassicalOnly, 0.6f, 
                "Fallback to classical algorithms");
        }

        private string GetStrongerPqcKemAlgorithm(string currentAlgorithm)
        {
            return currentAlgorithm switch
            {
                "ML-KEM-768" => "ML-KEM-1024",
                "ML-KEM-512" => "ML-KEM-768",
                _ => "ML-KEM-1024"
            };
        }

        private string GetStrongerPqcSignatureAlgorithm(string currentAlgorithm)
        {
            return currentAlgorithm switch
            {
                "ML-DSA-65" => "ML-DSA-87",
                "ML-DSA-44" => "ML-DSA-65",
                _ => "ML-DSA-87"
            };
        }

        private void ValidateAlgorithmSupport(AlgorithmSelectionResult result)
        {
            if (!_cryptographicProvider.IsAlgorithmSupported(result.Primary))
            {
                _logger.LogWarning("Primary algorithm {Algorithm} is not supported", result.Primary);
            }

            if (!string.IsNullOrEmpty(result.Fallback) && !_cryptographicProvider.IsAlgorithmSupported(result.Fallback))
            {
                _logger.LogWarning("Fallback algorithm {Algorithm} is not supported", result.Fallback);
            }
        }

        #endregion
    }

    /// <summary>
    /// Represents the result of algorithm selection.
    /// </summary>
    public class AlgorithmSelectionResult
    {
        /// <summary>
        /// Gets or sets the primary algorithm to use.
        /// </summary>
        public string Primary { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the fallback algorithm to use if the primary fails.
        /// </summary>
        public string? Fallback { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether this is a hybrid selection.
        /// </summary>
        public bool IsHybrid { get; set; }
    }

    /// <summary>
    /// Represents a strategy recommendation with confidence scoring.
    /// </summary>
    public class StrategyRecommendation
    {
        /// <summary>
        /// Gets the recommended encryption strategy.
        /// </summary>
        public EncryptionStrategy Strategy { get; }

        /// <summary>
        /// Gets the confidence score (0.0 to 1.0) for this recommendation.
        /// </summary>
        public float ConfidenceScore { get; }

        /// <summary>
        /// Gets the reasoning behind this recommendation.
        /// </summary>
        public string Reasoning { get; }

        /// <summary>
        /// Initializes a new instance of the <see cref="StrategyRecommendation"/> class.
        /// </summary>
        /// <param name="strategy">The recommended strategy</param>
        /// <param name="confidenceScore">The confidence score</param>
        /// <param name="reasoning">The reasoning behind the recommendation</param>
        public StrategyRecommendation(EncryptionStrategy strategy, float confidenceScore, string reasoning)
        {
            Strategy = strategy;
            ConfidenceScore = Math.Max(0.0f, Math.Min(1.0f, confidenceScore));
            Reasoning = reasoning ?? throw new ArgumentNullException(nameof(reasoning));
        }
    }

    /// <summary>
    /// Represents performance requirements for algorithm selection.
    /// </summary>
    public class PerformanceRequirements
    {
        /// <summary>
        /// Gets or sets a value indicating whether the operation requires fast execution.
        /// </summary>
        public bool RequireFastOperation { get; set; }

        /// <summary>
        /// Gets or sets the maximum acceptable operation time in seconds.
        /// </summary>
        public double MaxOperationTimeSeconds { get; set; } = 2.0;

        /// <summary>
        /// Gets or sets the maximum acceptable memory usage in bytes.
        /// </summary>
        public long MaxMemoryUsageBytes { get; set; } = 100 * 1024 * 1024; // 100MB default

        /// <summary>
        /// Gets or sets a value indicating whether constant-time operations are required.
        /// </summary>
        public bool RequireConstantTime { get; set; } = true;
    }
}