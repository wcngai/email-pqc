using System;
using System.Collections.Generic;
using System.Linq;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Policies.Engines
{
    /// <summary>
    /// Implements algorithm enforcement and fallback logic for PQC email encryption policies.
    /// </summary>
    public class AlgorithmEnforcementEngine : IAlgorithmEnforcementEngine
    {
        private readonly ILogger<AlgorithmEnforcementEngine> _logger;

        // Algorithm security level mappings
        private static readonly Dictionary<string, SecurityLevel> AlgorithmSecurityLevels = new(StringComparer.OrdinalIgnoreCase)
        {
            // Post-Quantum KEM Algorithms
            ["ML-KEM-512"] = SecurityLevel.Standard,
            ["ML-KEM-768"] = SecurityLevel.High,
            ["ML-KEM-1024"] = SecurityLevel.Critical,
            ["Kyber512"] = SecurityLevel.Standard,
            ["Kyber768"] = SecurityLevel.High,
            ["Kyber1024"] = SecurityLevel.Critical,

            // Post-Quantum Signature Algorithms
            ["ML-DSA-44"] = SecurityLevel.Standard,
            ["ML-DSA-65"] = SecurityLevel.High,
            ["ML-DSA-87"] = SecurityLevel.Critical,
            ["Dilithium2"] = SecurityLevel.Standard,
            ["Dilithium3"] = SecurityLevel.High,
            ["Dilithium5"] = SecurityLevel.Critical,

            // Classical KEM/RSA Algorithms
            ["RSA-OAEP-1024"] = SecurityLevel.Low,
            ["RSA-OAEP-2048"] = SecurityLevel.Standard,
            ["RSA-OAEP-3072"] = SecurityLevel.High,
            ["RSA-OAEP-4096"] = SecurityLevel.Critical,

            // Classical Signature Algorithms
            ["RSA-PSS-1024"] = SecurityLevel.Low,
            ["RSA-PSS-2048"] = SecurityLevel.Standard,
            ["RSA-PSS-3072"] = SecurityLevel.High,
            ["RSA-PSS-4096"] = SecurityLevel.Critical,
            ["ECDSA-P256"] = SecurityLevel.Standard,
            ["ECDSA-P384"] = SecurityLevel.High,
            ["ECDSA-P521"] = SecurityLevel.Critical,

            // Symmetric Algorithms
            ["AES-128-GCM"] = SecurityLevel.Standard,
            ["AES-192-GCM"] = SecurityLevel.High,
            ["AES-256-GCM"] = SecurityLevel.Critical,
            ["ChaCha20-Poly1305"] = SecurityLevel.High,

            // Hash Algorithms
            ["SHA-256"] = SecurityLevel.High,
            ["SHA-384"] = SecurityLevel.High,
            ["SHA-512"] = SecurityLevel.Critical,
            ["SHA3-256"] = SecurityLevel.High,
            ["SHA3-512"] = SecurityLevel.Critical
        };

        // Weak algorithms that should be prohibited
        private static readonly HashSet<string> WeakAlgorithms = new(StringComparer.OrdinalIgnoreCase)
        {
            "MD5", "SHA1", "SHA-1", "DES", "3DES", "RC4", 
            "RSA-1024", "RSA-OAEP-1024", "RSA-PSS-1024",
            "DSA-1024", "ECDSA-P192"
        };

        // Algorithm preference order (higher is better)
        private static readonly Dictionary<AlgorithmType, List<string>> PreferredAlgorithmOrder = new()
        {
            [AlgorithmType.Kem] = new()
            {
                "ML-KEM-1024", "ML-KEM-768", "ML-KEM-512",
                "Kyber1024", "Kyber768", "Kyber512",
                "RSA-OAEP-4096", "RSA-OAEP-3072", "RSA-OAEP-2048"
            },
            [AlgorithmType.Signature] = new()
            {
                "ML-DSA-87", "ML-DSA-65", "ML-DSA-44",
                "Dilithium5", "Dilithium3", "Dilithium2",
                "RSA-PSS-4096", "RSA-PSS-3072", "RSA-PSS-2048",
                "ECDSA-P521", "ECDSA-P384", "ECDSA-P256"
            },
            [AlgorithmType.Symmetric] = new()
            {
                "AES-256-GCM", "ChaCha20-Poly1305", "AES-192-GCM", "AES-128-GCM"
            },
            [AlgorithmType.Hash] = new()
            {
                "SHA3-512", "SHA-512", "SHA3-256", "SHA-384", "SHA-256"
            }
        };

        /// <summary>
        /// Initializes a new instance of the <see cref="AlgorithmEnforcementEngine"/> class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        public AlgorithmEnforcementEngine(ILogger<AlgorithmEnforcementEngine> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Enforces algorithm restrictions based on security policies.
        /// </summary>
        /// <param name="requestedAlgorithm">The requested algorithm</param>
        /// <param name="algorithmType">The type of algorithm</param>
        /// <param name="securityPolicy">The security policy to enforce</param>
        /// <returns>The algorithm enforcement result</returns>
        public AlgorithmEnforcementResult EnforceAlgorithmRestrictions(
            string requestedAlgorithm, 
            AlgorithmType algorithmType, 
            SecurityPolicy securityPolicy)
        {
            if (string.IsNullOrEmpty(requestedAlgorithm))
                throw new ArgumentException("Requested algorithm cannot be null or empty", nameof(requestedAlgorithm));
            
            if (securityPolicy == null)
                throw new ArgumentNullException(nameof(securityPolicy));

            var result = new AlgorithmEnforcementResult();

            _logger.LogDebug("Evaluating algorithm restrictions for {Algorithm} (type: {Type})", 
                requestedAlgorithm, algorithmType);

            // Check if algorithm is explicitly prohibited
            if (securityPolicy.ProhibitedAlgorithms.Contains(requestedAlgorithm))
            {
                result.IsAllowed = false;
                result.RejectReason = $"Algorithm '{requestedAlgorithm}' is explicitly prohibited by security policy";
                result.Violations.Add(new PolicyViolation
                {
                    Type = ViolationType.AlgorithmRestriction,
                    Severity = ViolationSeverity.High,
                    Message = result.RejectReason,
                    PolicySetting = "ProhibitedAlgorithms",
                    AttemptedValue = requestedAlgorithm
                });

                _logger.LogWarning("Algorithm {Algorithm} is explicitly prohibited", requestedAlgorithm);
                PopulateSuggestedAlternatives(result, algorithmType, securityPolicy);
                return result;
            }

            // Check if algorithm is weak and weak algorithms are prohibited
            if (securityPolicy.ProhibitWeakAlgorithms && IsWeakAlgorithm(requestedAlgorithm))
            {
                result.IsAllowed = false;
                result.RejectReason = $"Algorithm '{requestedAlgorithm}' is considered weak and prohibited by security policy";
                result.Violations.Add(new PolicyViolation
                {
                    Type = ViolationType.SecurityViolation,
                    Severity = ViolationSeverity.High,
                    Message = result.RejectReason,
                    PolicySetting = "ProhibitWeakAlgorithms",
                    AttemptedValue = requestedAlgorithm
                });

                _logger.LogWarning("Algorithm {Algorithm} is weak and prohibited", requestedAlgorithm);
                PopulateSuggestedAlternatives(result, algorithmType, securityPolicy);
                return result;
            }

            // Check minimum security level requirements
            if (!ValidateAlgorithmSecurity(requestedAlgorithm, algorithmType, securityPolicy.MinimumSecurityLevel))
            {
                result.IsAllowed = false;
                result.RejectReason = $"Algorithm '{requestedAlgorithm}' does not meet minimum security level requirement ({securityPolicy.MinimumSecurityLevel})";
                result.Violations.Add(new PolicyViolation
                {
                    Type = ViolationType.SecurityViolation,
                    Severity = ViolationSeverity.Medium,
                    Message = result.RejectReason,
                    PolicySetting = "MinimumSecurityLevel",
                    AttemptedValue = requestedAlgorithm,
                    ExpectedValue = securityPolicy.MinimumSecurityLevel
                });

                _logger.LogWarning("Algorithm {Algorithm} does not meet minimum security level {MinLevel}", 
                    requestedAlgorithm, securityPolicy.MinimumSecurityLevel);
                PopulateSuggestedAlternatives(result, algorithmType, securityPolicy);
                return result;
            }

            // Check RSA-specific key size requirements
            if (IsRsaAlgorithm(requestedAlgorithm))
            {
                var keySize = ExtractRsaKeySize(requestedAlgorithm);
                if (keySize > 0 && keySize < securityPolicy.MinimumRsaKeySize)
                {
                    result.IsAllowed = false;
                    result.RejectReason = $"RSA key size {keySize} bits is below minimum requirement of {securityPolicy.MinimumRsaKeySize} bits";
                    result.Violations.Add(new PolicyViolation
                    {
                        Type = ViolationType.AlgorithmRestriction,
                        Severity = ViolationSeverity.High,
                        Message = result.RejectReason,
                        PolicySetting = "MinimumRsaKeySize",
                        AttemptedValue = keySize,
                        ExpectedValue = securityPolicy.MinimumRsaKeySize
                    });

                    _logger.LogWarning("RSA key size {KeySize} is below minimum requirement {MinSize}", 
                        keySize, securityPolicy.MinimumRsaKeySize);
                    PopulateSuggestedAlternatives(result, algorithmType, securityPolicy);
                    return result;
                }
            }

            // Algorithm passes all checks
            result.IsAllowed = true;
            _logger.LogDebug("Algorithm {Algorithm} passed all security policy checks", requestedAlgorithm);

            return result;
        }

        /// <summary>
        /// Gets the fallback algorithm sequence based on policy and availability.
        /// </summary>
        /// <param name="preferredAlgorithm">The preferred algorithm</param>
        /// <param name="algorithmType">The type of algorithm</param>
        /// <param name="fallbackPolicy">The fallback policy</param>
        /// <param name="availableAlgorithms">The list of available algorithms</param>
        /// <returns>The ordered list of algorithms to try</returns>
        public IEnumerable<string> GetFallbackSequence(
            string preferredAlgorithm, 
            AlgorithmType algorithmType, 
            FallbackPolicy fallbackPolicy, 
            IEnumerable<string> availableAlgorithms)
        {
            if (string.IsNullOrEmpty(preferredAlgorithm))
                throw new ArgumentException("Preferred algorithm cannot be null or empty", nameof(preferredAlgorithm));
            
            if (fallbackPolicy == null)
                throw new ArgumentNullException(nameof(fallbackPolicy));

            if (availableAlgorithms == null)
                throw new ArgumentNullException(nameof(availableAlgorithms));

            var sequence = new List<string>();
            var availableList = availableAlgorithms.ToList();

            _logger.LogDebug("Building fallback sequence for {Algorithm} (type: {Type}), available algorithms: {Count}", 
                preferredAlgorithm, algorithmType, availableList.Count);

            // Start with preferred algorithm if available
            if (availableList.Contains(preferredAlgorithm, StringComparer.OrdinalIgnoreCase))
            {
                sequence.Add(preferredAlgorithm);
            }

            // Use custom fallback sequence if defined
            if (fallbackPolicy.CustomFallbackSequence?.Any() == true)
            {
                var customAlgorithms = algorithmType switch
                {
                    AlgorithmType.Kem => fallbackPolicy.CustomFallbackSequence.Select(s => s.KemAlgorithm),
                    AlgorithmType.Signature => fallbackPolicy.CustomFallbackSequence.Select(s => s.SignatureAlgorithm),
                    _ => Enumerable.Empty<string>()
                };

                foreach (var algorithm in customAlgorithms.Where(a => !string.IsNullOrEmpty(a)))
                {
                    if (availableList.Contains(algorithm, StringComparer.OrdinalIgnoreCase) && 
                        !sequence.Contains(algorithm, StringComparer.OrdinalIgnoreCase))
                    {
                        sequence.Add(algorithm);
                    }
                }
            }

            // Add algorithms from preferred order that are available
            if (PreferredAlgorithmOrder.TryGetValue(algorithmType, out var preferredOrder))
            {
                foreach (var algorithm in preferredOrder)
                {
                    if (availableList.Contains(algorithm, StringComparer.OrdinalIgnoreCase) && 
                        !sequence.Contains(algorithm, StringComparer.OrdinalIgnoreCase))
                    {
                        sequence.Add(algorithm);
                    }
                }
            }

            // Add any remaining available algorithms
            foreach (var algorithm in availableList)
            {
                if (!sequence.Contains(algorithm, StringComparer.OrdinalIgnoreCase))
                {
                    sequence.Add(algorithm);
                }
            }

            // Limit sequence length based on fallback policy
            var maxAttempts = Math.Min(fallbackPolicy.MaxFallbackAttempts, sequence.Count);
            var finalSequence = sequence.Take(maxAttempts).ToList();

            _logger.LogInformation("Generated fallback sequence for {Algorithm}: [{Sequence}]", 
                preferredAlgorithm, string.Join(", ", finalSequence));

            return finalSequence;
        }

        /// <summary>
        /// Validates that an algorithm meets the minimum security requirements.
        /// </summary>
        /// <param name="algorithm">The algorithm to validate</param>
        /// <param name="algorithmType">The type of algorithm</param>
        /// <param name="minimumSecurityLevel">The minimum required security level</param>
        /// <returns>True if the algorithm meets the requirements</returns>
        public bool ValidateAlgorithmSecurity(
            string algorithm, 
            AlgorithmType algorithmType, 
            SecurityLevel minimumSecurityLevel)
        {
            if (string.IsNullOrEmpty(algorithm))
                return false;

            // Check if algorithm has a known security level
            if (AlgorithmSecurityLevels.TryGetValue(algorithm, out var algorithmLevel))
            {
                var isValid = algorithmLevel >= minimumSecurityLevel;
                _logger.LogDebug("Algorithm {Algorithm} security level: {AlgorithmLevel}, required: {MinimumLevel}, valid: {IsValid}", 
                    algorithm, algorithmLevel, minimumSecurityLevel, isValid);
                return isValid;
            }

            // For unknown algorithms, be conservative and require explicit approval
            _logger.LogWarning("Unknown algorithm security level for {Algorithm}, rejecting for security", algorithm);
            return false;
        }

        #region Private Methods

        /// <summary>
        /// Checks if the algorithm is considered weak.
        /// </summary>
        /// <param name="algorithm">The algorithm to check</param>
        /// <returns>True if the algorithm is weak</returns>
        private static bool IsWeakAlgorithm(string algorithm)
        {
            return WeakAlgorithms.Contains(algorithm);
        }

        /// <summary>
        /// Checks if the algorithm is an RSA-based algorithm.
        /// </summary>
        /// <param name="algorithm">The algorithm to check</param>
        /// <returns>True if it's an RSA algorithm</returns>
        private static bool IsRsaAlgorithm(string algorithm)
        {
            return algorithm.StartsWith("RSA", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Extracts the key size from an RSA algorithm name.
        /// </summary>
        /// <param name="algorithm">The RSA algorithm name</param>
        /// <returns>The key size in bits, or 0 if not found</returns>
        private static int ExtractRsaKeySize(string algorithm)
        {
            // Extract numbers from algorithm name (e.g., "RSA-OAEP-2048" -> 2048)
            var parts = algorithm.Split('-');
            foreach (var part in parts.Reverse()) // Check from the end
            {
                if (int.TryParse(part, out var keySize) && keySize > 0)
                {
                    return keySize;
                }
            }
            return 0;
        }

        /// <summary>
        /// Populates suggested alternative algorithms for the given type and security requirements.
        /// </summary>
        /// <param name="result">The enforcement result to populate</param>
        /// <param name="algorithmType">The type of algorithm</param>
        /// <param name="securityPolicy">The security policy requirements</param>
        private void PopulateSuggestedAlternatives(
            AlgorithmEnforcementResult result, 
            AlgorithmType algorithmType, 
            SecurityPolicy securityPolicy)
        {
            if (!PreferredAlgorithmOrder.TryGetValue(algorithmType, out var algorithmOrder))
                return;

            foreach (var algorithm in algorithmOrder)
            {
                if (ValidateAlgorithmSecurity(algorithm, algorithmType, securityPolicy.MinimumSecurityLevel) &&
                    !securityPolicy.ProhibitedAlgorithms.Contains(algorithm) &&
                    !(securityPolicy.ProhibitWeakAlgorithms && IsWeakAlgorithm(algorithm)))
                {
                    // For RSA algorithms, check key size requirements
                    if (IsRsaAlgorithm(algorithm))
                    {
                        var keySize = ExtractRsaKeySize(algorithm);
                        if (keySize > 0 && keySize < securityPolicy.MinimumRsaKeySize)
                            continue;
                    }

                    result.SuggestedAlternatives.Add(algorithm);
                    
                    // Limit suggestions to avoid overwhelming output
                    if (result.SuggestedAlternatives.Count >= 3)
                        break;
                }
            }

            if (result.SuggestedAlternatives.Any())
            {
                _logger.LogDebug("Suggested {Count} alternative algorithms for type {Type}", 
                    result.SuggestedAlternatives.Count, algorithmType);
            }
        }

        #endregion
    }
}