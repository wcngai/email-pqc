using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Policies.Engines
{
    /// <summary>
    /// Implements the main policy engine for PQC email encryption policies.
    /// </summary>
    public class PqcEmailPolicyEngine : IPolicyEngine
    {
        private readonly ILogger<PqcEmailPolicyEngine> _logger;
        private readonly IDomainRuleEngine _domainRuleEngine;
        private readonly IAlgorithmEnforcementEngine _algorithmEnforcementEngine;
        private readonly IPolicyAuditLogger _auditLogger;
        private readonly List<IPolicySourceProvider> _policySourceProviders;
        
        private PqcEmailPolicy? _cachedPolicy;
        private DateTime _lastPolicyUpdate = DateTime.MinValue;
        private readonly object _policyLock = new object();

        /// <summary>
        /// Event raised when policy configuration is updated.
        /// </summary>
        public event EventHandler<PolicyUpdatedEventArgs>? PolicyUpdated;

        /// <summary>
        /// Event raised when a policy violation is detected.
        /// </summary>
        public event EventHandler<PolicyViolationEventArgs>? PolicyViolationDetected;

        /// <summary>
        /// Initializes a new instance of the <see cref="PqcEmailPolicyEngine"/> class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="domainRuleEngine">The domain rule engine</param>
        /// <param name="algorithmEnforcementEngine">The algorithm enforcement engine</param>
        /// <param name="auditLogger">The audit logger</param>
        /// <param name="policySourceProviders">The list of policy source providers</param>
        public PqcEmailPolicyEngine(
            ILogger<PqcEmailPolicyEngine> logger,
            IDomainRuleEngine domainRuleEngine,
            IAlgorithmEnforcementEngine algorithmEnforcementEngine,
            IPolicyAuditLogger auditLogger,
            IEnumerable<IPolicySourceProvider> policySourceProviders)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _domainRuleEngine = domainRuleEngine ?? throw new ArgumentNullException(nameof(domainRuleEngine));
            _algorithmEnforcementEngine = algorithmEnforcementEngine ?? throw new ArgumentNullException(nameof(algorithmEnforcementEngine));
            _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
            _policySourceProviders = policySourceProviders?.ToList() ?? throw new ArgumentNullException(nameof(policySourceProviders));

            // Subscribe to policy source updates
            foreach (var provider in _policySourceProviders)
            {
                provider.PolicySourceUpdated += OnPolicySourceUpdated;
            }
        }

        /// <summary>
        /// Evaluates policies for a specific recipient and returns the effective configuration.
        /// </summary>
        /// <param name="recipientEmail">The recipient's email address</param>
        /// <param name="senderEmail">The sender's email address (optional)</param>
        /// <param name="context">Additional context for policy evaluation</param>
        /// <returns>The policy evaluation result with effective configuration</returns>
        public async Task<PolicyEvaluationResult> EvaluatePolicyAsync(
            string recipientEmail, 
            string? senderEmail = null, 
            Dictionary<string, object>? context = null)
        {
            if (string.IsNullOrEmpty(recipientEmail))
                throw new ArgumentException("Recipient email cannot be null or empty", nameof(recipientEmail));

            return await EvaluatePolicyAsync(new[] { recipientEmail }, senderEmail, context);
        }

        /// <summary>
        /// Evaluates policies for multiple recipients and returns the effective configuration.
        /// </summary>
        /// <param name="recipientEmails">The list of recipient email addresses</param>
        /// <param name="senderEmail">The sender's email address (optional)</param>
        /// <param name="context">Additional context for policy evaluation</param>
        /// <returns>The policy evaluation result with effective configuration</returns>
        public async Task<PolicyEvaluationResult> EvaluatePolicyAsync(
            IEnumerable<string> recipientEmails, 
            string? senderEmail = null, 
            Dictionary<string, object>? context = null)
        {
            if (recipientEmails == null)
                throw new ArgumentNullException(nameof(recipientEmails));

            var recipients = recipientEmails.ToList();
            if (!recipients.Any())
                throw new ArgumentException("At least one recipient email must be provided", nameof(recipientEmails));

            _logger.LogDebug("Evaluating policy for {RecipientCount} recipients from sender {Sender}", 
                recipients.Count, senderEmail ?? "unknown");

            var effectivePolicy = await GetEffectivePolicyAsync();
            var result = new PolicyEvaluationResult
            {
                Context = context ?? new Dictionary<string, object>()
            };

            // Add evaluation context
            result.Context["RecipientEmails"] = recipients;
            result.Context["SenderEmail"] = senderEmail;
            result.Context["EvaluationTimestamp"] = DateTime.UtcNow;

            // Start with global policy as baseline
            var baselineConfig = CreateAlgorithmConfiguration(effectivePolicy.GlobalCryptographic);
            result.EffectiveConfiguration = baselineConfig;
            
            result.AppliedPolicies.Add(new AppliedPolicy
            {
                Source = PolicySource.Default,
                Description = "Global cryptographic policy",
                Precedence = 100,
                Settings = new Dictionary<string, object>
                {
                    ["Mode"] = effectivePolicy.GlobalCryptographic.Mode,
                    ["PreferredKemAlgorithm"] = effectivePolicy.GlobalCryptographic.PreferredKemAlgorithm,
                    ["PreferredSignatureAlgorithm"] = effectivePolicy.GlobalCryptographic.PreferredSignatureAlgorithm
                }
            });

            // Evaluate domain rules for all recipients
            var domainResults = new List<DomainRuleResult>();
            var mostRestrictiveResult = new DomainRuleResult();

            foreach (var recipient in recipients)
            {
                var domainResult = _domainRuleEngine.EvaluateDomainRules(recipient, effectivePolicy.Domain);
                domainResults.Add(domainResult);

                // Apply most restrictive rules across all recipients
                if (domainResult.RequiresPqc)
                    mostRestrictiveResult.RequiresPqc = true;
                if (domainResult.RequiresEncryption)
                    mostRestrictiveResult.RequiresEncryption = true;
                if (!domainResult.AllowsClassicalOnly)
                    mostRestrictiveResult.AllowsClassicalOnly = false;

                // Check for recipient-specific overrides
                if (effectivePolicy.Domain.RecipientOverrides.TryGetValue(recipient, out var recipientOverride))
                {
                    await ApplyRecipientOverride(result, recipient, recipientOverride);
                }
            }

            // Apply domain rule results
            result.RequireEncryption = mostRestrictiveResult.RequiresEncryption;
            
            if (mostRestrictiveResult.RequiresPqc)
            {
                // Force PQC mode if required by domain rules
                var pqcConfig = AlgorithmConfiguration.CreatePostQuantumOnly();
                result.EffectiveConfiguration = pqcConfig;
                
                result.AppliedPolicies.Add(new AppliedPolicy
                {
                    Source = PolicySource.DomainOverride,
                    Description = "Domain requires PQC encryption",
                    Precedence = 200,
                    Settings = new Dictionary<string, object> { ["Mode"] = CryptographicMode.PostQuantumOnly }
                });
            }
            else if (mostRestrictiveResult.AllowsClassicalOnly && 
                     effectivePolicy.GlobalCryptographic.Mode == CryptographicMode.Hybrid)
            {
                // Allow classical-only if explicitly permitted and not in PQC-only mode
                result.AppliedPolicies.Add(new AppliedPolicy
                {
                    Source = PolicySource.DomainOverride,
                    Description = "Domain allows classical-only encryption",
                    Precedence = 150,
                    Settings = new Dictionary<string, object> { ["AllowsClassicalOnly"] = true }
                });
            }

            // Apply fallback policy settings
            result.AllowUnencryptedFallback = effectivePolicy.Fallback.AllowUnencryptedFallback && 
                                              !result.RequireEncryption;

            // Validate algorithms against security policies
            await ValidateEffectiveAlgorithms(result, effectivePolicy.Security);

            // Log policy evaluation
            var auditEvent = new PolicyAuditEvent
            {
                EventType = "PolicyEvaluation",
                Actor = senderEmail,
                RecipientEmail = string.Join(", ", recipients),
                SenderEmail = senderEmail,
                PolicyDecision = result.EffectiveConfiguration.Mode.ToString(),
                AlgorithmsUsed = new Dictionary<string, string>
                {
                    ["KEM"] = result.EffectiveConfiguration.PreferredKemAlgorithm,
                    ["Signature"] = result.EffectiveConfiguration.PreferredSignatureAlgorithm
                },
                Outcome = result.Violations.Any() ? PolicyOutcome.Violation : PolicyOutcome.Success,
                EventData = result.Context
            };

            await _auditLogger.LogPolicyDecisionAsync(auditEvent);

            _logger.LogInformation("Policy evaluation completed for {RecipientCount} recipients: Mode={Mode}, RequireEncryption={RequireEncryption}, Violations={ViolationCount}", 
                recipients.Count, result.EffectiveConfiguration.Mode, result.RequireEncryption, result.Violations.Count);

            return result;
        }

        /// <summary>
        /// Validates that the specified algorithm is allowed by current policies.
        /// </summary>
        /// <param name="algorithm">The algorithm to validate</param>
        /// <param name="algorithmType">The type of algorithm (KEM, Signature, etc.)</param>
        /// <param name="context">Additional context for validation</param>
        /// <returns>True if the algorithm is allowed, false otherwise</returns>
        public async Task<bool> ValidateAlgorithmAsync(
            string algorithm, 
            AlgorithmType algorithmType, 
            Dictionary<string, object>? context = null)
        {
            if (string.IsNullOrEmpty(algorithm))
                return false;

            var effectivePolicy = await GetEffectivePolicyAsync();
            var enforcementResult = _algorithmEnforcementEngine.EnforceAlgorithmRestrictions(
                algorithm, algorithmType, effectivePolicy.Security);

            if (!enforcementResult.IsAllowed)
            {
                _logger.LogWarning("Algorithm {Algorithm} validation failed: {Reason}", 
                    algorithm, enforcementResult.RejectReason);

                // Log violations
                foreach (var violation in enforcementResult.Violations)
                {
                    await _auditLogger.LogPolicyViolationAsync(violation, context);
                    PolicyViolationDetected?.Invoke(this, new PolicyViolationEventArgs(violation, context));
                }
            }

            return enforcementResult.IsAllowed;
        }

        /// <summary>
        /// Gets the current effective policy configuration.
        /// </summary>
        /// <returns>The current policy configuration</returns>
        public async Task<PqcEmailPolicy> GetEffectivePolicyAsync()
        {
            lock (_policyLock)
            {
                if (_cachedPolicy != null && 
                    (DateTime.UtcNow - _lastPolicyUpdate).TotalMinutes < 5) // Cache for 5 minutes
                {
                    return _cachedPolicy;
                }
            }

            await ReloadPolicyAsync();
            
            lock (_policyLock)
            {
                return _cachedPolicy ?? CreateDefaultPolicy();
            }
        }

        /// <summary>
        /// Reloads the policy configuration from all sources.
        /// </summary>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task ReloadPolicyAsync()
        {
            _logger.LogDebug("Reloading policy configuration from {ProviderCount} sources", _policySourceProviders.Count);

            // Load policies from all sources, ordered by priority
            var sourcePolicies = new List<(PolicySource Source, PqcEmailPolicy Policy, int Priority)>();

            foreach (var provider in _policySourceProviders.OrderByDescending(p => p.Priority))
            {
                try
                {
                    if (await provider.IsAvailableAsync())
                    {
                        var policy = await provider.GetPolicyAsync();
                        if (policy != null)
                        {
                            sourcePolicies.Add((provider.SourceType, policy, provider.Priority));
                            _logger.LogDebug("Loaded policy from source {Source} with priority {Priority}", 
                                provider.SourceType, provider.Priority);
                        }
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to load policy from source {Source}", provider.SourceType);
                }
            }

            // Merge policies (higher priority overrides lower priority)
            var effectivePolicy = MergePolicies(sourcePolicies);

            lock (_policyLock)
            {
                var previousPolicy = _cachedPolicy;
                _cachedPolicy = effectivePolicy;
                _lastPolicyUpdate = DateTime.UtcNow;

                if (previousPolicy == null || !PoliciesEqual(previousPolicy, effectivePolicy))
                {
                    _logger.LogInformation("Policy configuration updated from {SourceCount} sources", sourcePolicies.Count);
                    PolicyUpdated?.Invoke(this, new PolicyUpdatedEventArgs(effectivePolicy, PolicySource.GroupPolicy));
                }
            }
        }

        /// <summary>
        /// Logs an audit event for policy enforcement.
        /// </summary>
        /// <param name="auditEvent">The audit event to log</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task LogAuditEventAsync(PolicyAuditEvent auditEvent)
        {
            if (auditEvent == null)
                throw new ArgumentNullException(nameof(auditEvent));

            await _auditLogger.LogPolicyDecisionAsync(auditEvent);
        }

        #region Private Methods

        /// <summary>
        /// Creates an AlgorithmConfiguration from GlobalCryptographicPolicy.
        /// </summary>
        /// <param name="globalPolicy">The global cryptographic policy</param>
        /// <returns>The algorithm configuration</returns>
        private static AlgorithmConfiguration CreateAlgorithmConfiguration(GlobalCryptographicPolicy globalPolicy)
        {
            return new AlgorithmConfiguration(
                globalPolicy.Mode,
                globalPolicy.PreferredKemAlgorithm,
                globalPolicy.PreferredSignatureAlgorithm,
                globalPolicy.FallbackKemAlgorithm,
                globalPolicy.FallbackSignatureAlgorithm,
                "AES-256-GCM", // Default symmetric algorithm
                "SHA-256",     // Default hash algorithm
                globalPolicy.AlwaysCreateDualSignatures
            );
        }

        /// <summary>
        /// Creates a default policy configuration.
        /// </summary>
        /// <returns>The default policy</returns>
        private static PqcEmailPolicy CreateDefaultPolicy()
        {
            return new PqcEmailPolicy
            {
                GlobalCryptographic = new GlobalCryptographicPolicy(),
                Security = new SecurityPolicy(),
                Domain = new DomainPolicy(),
                Inheritance = new InheritancePolicy(),
                Fallback = new FallbackPolicy(),
                Audit = new AuditPolicy(),
                Performance = new PerformancePolicy(),
                Certificate = new CertificatePolicy(),
                Source = PolicySource.Default
            };
        }

        /// <summary>
        /// Applies recipient-specific policy overrides.
        /// </summary>
        /// <param name="result">The policy evaluation result</param>
        /// <param name="recipient">The recipient email</param>
        /// <param name="recipientOverride">The recipient override policy</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ApplyRecipientOverride(
            PolicyEvaluationResult result, 
            string recipient, 
            RecipientSpecificPolicy recipientOverride)
        {
            // Check if override is still valid
            if (recipientOverride.ExpiresAt.HasValue && recipientOverride.ExpiresAt.Value < DateTime.UtcNow)
            {
                _logger.LogWarning("Recipient override for {Recipient} has expired", recipient);
                return;
            }

            var overrideSettings = new Dictionary<string, object>();

            // Apply mode override
            if (recipientOverride.ModeOverride.HasValue)
            {
                result.EffectiveConfiguration = recipientOverride.ModeOverride.Value switch
                {
                    CryptographicMode.ClassicalOnly => AlgorithmConfiguration.CreateClassicalOnly(),
                    CryptographicMode.PostQuantumOnly => AlgorithmConfiguration.CreatePostQuantumOnly(),
                    CryptographicMode.Hybrid => AlgorithmConfiguration.CreateDefault(),
                    _ => result.EffectiveConfiguration
                };
                overrideSettings["Mode"] = recipientOverride.ModeOverride.Value;
            }

            // Apply algorithm overrides
            if (recipientOverride.AlgorithmOverrides != null)
            {
                var overrides = recipientOverride.AlgorithmOverrides;
                if (!string.IsNullOrEmpty(overrides.PreferredKemAlgorithm))
                {
                    overrideSettings["PreferredKemAlgorithm"] = overrides.PreferredKemAlgorithm;
                }
                if (!string.IsNullOrEmpty(overrides.PreferredSignatureAlgorithm))
                {
                    overrideSettings["PreferredSignatureAlgorithm"] = overrides.PreferredSignatureAlgorithm;
                }
            }

            // Apply unencrypted allowance
            if (recipientOverride.AllowUnencrypted.HasValue)
            {
                result.AllowUnencryptedFallback = recipientOverride.AllowUnencrypted.Value;
                overrideSettings["AllowUnencrypted"] = recipientOverride.AllowUnencrypted.Value;
            }

            if (overrideSettings.Any())
            {
                result.AppliedPolicies.Add(new AppliedPolicy
                {
                    Source = PolicySource.RecipientOverride,
                    Description = $"Recipient-specific override for {recipient}",
                    Precedence = 300,
                    Settings = overrideSettings
                });

                _logger.LogInformation("Applied recipient-specific override for {Recipient}", recipient);
            }

            await Task.CompletedTask;
        }

        /// <summary>
        /// Validates the effective algorithms against security policies.
        /// </summary>
        /// <param name="result">The policy evaluation result</param>
        /// <param name="securityPolicy">The security policy</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task ValidateEffectiveAlgorithms(PolicyEvaluationResult result, SecurityPolicy securityPolicy)
        {
            var algorithms = new[]
            {
                (result.EffectiveConfiguration.PreferredKemAlgorithm, AlgorithmType.Kem),
                (result.EffectiveConfiguration.PreferredSignatureAlgorithm, AlgorithmType.Signature),
                (result.EffectiveConfiguration.FallbackKemAlgorithm, AlgorithmType.Kem),
                (result.EffectiveConfiguration.FallbackSignatureAlgorithm, AlgorithmType.Signature)
            };

            foreach (var (algorithm, type) in algorithms)
            {
                if (string.IsNullOrEmpty(algorithm))
                    continue;

                var enforcementResult = _algorithmEnforcementEngine.EnforceAlgorithmRestrictions(
                    algorithm, type, securityPolicy);

                if (!enforcementResult.IsAllowed)
                {
                    result.Violations.AddRange(enforcementResult.Violations);
                    
                    foreach (var violation in enforcementResult.Violations)
                    {
                        await _auditLogger.LogPolicyViolationAsync(violation);
                        PolicyViolationDetected?.Invoke(this, new PolicyViolationEventArgs(violation));
                    }
                }
            }
        }

        /// <summary>
        /// Merges policies from multiple sources based on priority.
        /// </summary>
        /// <param name="sourcePolicies">The policies from different sources</param>
        /// <returns>The merged effective policy</returns>
        private PqcEmailPolicy MergePolicies(List<(PolicySource Source, PqcEmailPolicy Policy, int Priority)> sourcePolicies)
        {
            if (!sourcePolicies.Any())
                return CreateDefaultPolicy();

            // Start with the lowest priority policy as base
            var basePolicy = sourcePolicies.OrderBy(p => p.Priority).First().Policy;
            var effectivePolicy = CreateDefaultPolicy();

            // Copy base policy settings
            CopyPolicySettings(basePolicy, effectivePolicy);

            // Apply higher priority policies in order
            foreach (var (source, policy, priority) in sourcePolicies.OrderBy(p => p.Priority))
            {
                MergePolicySettings(policy, effectivePolicy, source);
            }

            effectivePolicy.LastUpdated = DateTime.UtcNow;
            return effectivePolicy;
        }

        /// <summary>
        /// Copies policy settings from source to destination.
        /// </summary>
        /// <param name="source">The source policy</param>
        /// <param name="destination">The destination policy</param>
        private static void CopyPolicySettings(PqcEmailPolicy source, PqcEmailPolicy destination)
        {
            // Copy all policy sections - in a production system, you might want more granular control
            destination.GlobalCryptographic = source.GlobalCryptographic;
            destination.Security = source.Security;
            destination.Domain = source.Domain;
            destination.Inheritance = source.Inheritance;
            destination.Fallback = source.Fallback;
            destination.Audit = source.Audit;
            destination.Performance = source.Performance;
            destination.Certificate = source.Certificate;
        }

        /// <summary>
        /// Merges policy settings from source into destination based on inheritance rules.
        /// </summary>
        /// <param name="source">The source policy to merge from</param>
        /// <param name="destination">The destination policy to merge into</param>
        /// <param name="sourceType">The type of the source policy</param>
        private static void MergePolicySettings(PqcEmailPolicy source, PqcEmailPolicy destination, PolicySource sourceType)
        {
            // In a production system, this would implement sophisticated merging logic
            // based on the inheritance policy and protected settings.
            // For now, higher priority sources override lower priority ones.
            
            if (sourceType == PolicySource.GroupPolicy || sourceType == PolicySource.Registry)
            {
                // Group Policy and Registry settings typically override others
                CopyPolicySettings(source, destination);
            }
        }

        /// <summary>
        /// Checks if two policies are equal.
        /// </summary>
        /// <param name="policy1">The first policy</param>
        /// <param name="policy2">The second policy</param>
        /// <returns>True if policies are equal</returns>
        private static bool PoliciesEqual(PqcEmailPolicy policy1, PqcEmailPolicy policy2)
        {
            // Simple equality check - in production, you might want a more sophisticated comparison
            return policy1.LastUpdated == policy2.LastUpdated &&
                   policy1.Version == policy2.Version;
        }

        /// <summary>
        /// Handles policy source update events.
        /// </summary>
        /// <param name="sender">The event sender</param>
        /// <param name="e">The event arguments</param>
        private async void OnPolicySourceUpdated(object? sender, PolicySourceUpdatedEventArgs e)
        {
            _logger.LogDebug("Policy source {Source} updated, reloading effective policy", e.SourceType);
            await ReloadPolicyAsync();
        }

        #endregion
    }
}