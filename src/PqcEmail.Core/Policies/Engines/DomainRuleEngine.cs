using System;
using System.Collections.Generic;
using System.Linq;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Policies.Engines
{
    /// <summary>
    /// Implements domain-based rule evaluation for PQC email encryption policies.
    /// </summary>
    public class DomainRuleEngine : IDomainRuleEngine
    {
        private readonly ILogger<DomainRuleEngine> _logger;
        
        /// <summary>
        /// Initializes a new instance of the <see cref="DomainRuleEngine"/> class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        public DomainRuleEngine(ILogger<DomainRuleEngine> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        /// <summary>
        /// Evaluates domain rules for the specified recipient.
        /// </summary>
        /// <param name="recipientEmail">The recipient's email address</param>
        /// <param name="domainPolicy">The domain policy to evaluate</param>
        /// <returns>The domain rule evaluation result</returns>
        public DomainRuleResult EvaluateDomainRules(string recipientEmail, DomainPolicy domainPolicy)
        {
            if (string.IsNullOrEmpty(recipientEmail))
                throw new ArgumentException("Recipient email cannot be null or empty", nameof(recipientEmail));
            
            if (domainPolicy == null)
                throw new ArgumentNullException(nameof(domainPolicy));

            var domain = ExtractDomain(recipientEmail);
            if (string.IsNullOrEmpty(domain))
            {
                _logger.LogWarning("Could not extract domain from email address: {Email}", recipientEmail);
                return new DomainRuleResult();
            }

            var result = new DomainRuleResult();
            
            _logger.LogDebug("Evaluating domain rules for recipient: {Email}, domain: {Domain}", 
                recipientEmail, domain);

            // Check Force PQC rules (highest priority)
            var forcePqcRule = FindMatchingRule(recipientEmail, domainPolicy.ForcePqcDomains);
            if (forcePqcRule != null)
            {
                result.RequiresPqc = true;
                result.RequiresEncryption = true;
                result.MatchedRules.Add(forcePqcRule);
                _logger.LogInformation("Domain {Domain} requires PQC encryption based on rule: {Rule}", 
                    domain, forcePqcRule.Pattern);
            }

            // Check Prohibit Unencrypted rules
            var prohibitUnencryptedRule = FindMatchingRule(recipientEmail, domainPolicy.ProhibitUnencryptedDomains);
            if (prohibitUnencryptedRule != null)
            {
                result.RequiresEncryption = true;
                result.MatchedRules.Add(prohibitUnencryptedRule);
                _logger.LogInformation("Domain {Domain} prohibits unencrypted email based on rule: {Rule}", 
                    domain, prohibitUnencryptedRule.Pattern);
            }

            // Check Allow Classical Only rules
            var allowClassicalRule = FindMatchingRule(recipientEmail, domainPolicy.AllowClassicalOnlyDomains);
            if (allowClassicalRule != null && !result.RequiresPqc)
            {
                result.AllowsClassicalOnly = true;
                result.MatchedRules.Add(allowClassicalRule);
                _logger.LogInformation("Domain {Domain} allows classical-only encryption based on rule: {Rule}", 
                    domain, allowClassicalRule.Pattern);
            }

            // Check for domain-specific overrides
            if (domainPolicy.DomainOverrides.TryGetValue(domain, out var domainOverride))
            {
                result.DomainOverrides = domainOverride;
                _logger.LogInformation("Found domain-specific policy override for domain: {Domain}", domain);
            }
            else
            {
                // Check for wildcard domain overrides
                var wildcardOverride = FindWildcardDomainOverride(domain, domainPolicy.DomainOverrides);
                if (wildcardOverride.HasValue)
                {
                    result.DomainOverrides = wildcardOverride.Value.Value;
                    _logger.LogInformation("Found wildcard domain-specific policy override for domain: {Domain} using pattern: {Pattern}", 
                        domain, wildcardOverride.Value.Key);
                }
            }

            // Apply domain-specific overrides to result
            if (result.DomainOverrides != null)
            {
                if (result.DomainOverrides.RequireEncryption.HasValue)
                {
                    result.RequiresEncryption = result.DomainOverrides.RequireEncryption.Value;
                }
            }

            _logger.LogDebug("Domain rule evaluation complete for {Email}: RequiresPqc={RequiresPqc}, RequiresEncryption={RequiresEncryption}, AllowsClassicalOnly={AllowsClassicalOnly}", 
                recipientEmail, result.RequiresPqc, result.RequiresEncryption, result.AllowsClassicalOnly);

            return result;
        }

        /// <summary>
        /// Checks if the recipient domain matches any of the specified rules.
        /// </summary>
        /// <param name="recipientEmail">The recipient's email address</param>
        /// <param name="rules">The rules to check</param>
        /// <returns>The matching rule or null if no match</returns>
        public DomainRule? FindMatchingRule(string recipientEmail, IEnumerable<DomainRule> rules)
        {
            if (string.IsNullOrEmpty(recipientEmail) || rules == null)
                return null;

            var domain = ExtractDomain(recipientEmail);
            if (string.IsNullOrEmpty(domain))
                return null;

            // Sort rules by priority (descending) and then check for matches
            var sortedRules = rules
                .Where(r => r.Enabled)
                .OrderByDescending(r => r.Priority)
                .ThenBy(r => r.Pattern);

            foreach (var rule in sortedRules)
            {
                if (rule.Matches(domain) || rule.Matches(recipientEmail))
                {
                    _logger.LogDebug("Rule match found: Pattern='{Pattern}', Domain='{Domain}', Priority={Priority}", 
                        rule.Pattern, domain, rule.Priority);
                    return rule;
                }
            }

            return null;
        }

        /// <summary>
        /// Validates and normalizes domain rules.
        /// </summary>
        /// <param name="rules">The rules to validate</param>
        /// <returns>The validation result</returns>
        public ValidationResult ValidateDomainRules(IEnumerable<DomainRule> rules)
        {
            var result = new ValidationResult();
            
            if (rules == null)
            {
                result.Errors.Add("Domain rules collection cannot be null");
                result.IsValid = false;
                return result;
            }

            var rulesList = rules.ToList();
            var seenPatterns = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var rule in rulesList)
            {
                // Validate pattern
                if (string.IsNullOrWhiteSpace(rule.Pattern))
                {
                    result.Errors.Add("Domain rule pattern cannot be empty");
                    result.IsValid = false;
                    continue;
                }

                // Check for duplicate patterns
                if (seenPatterns.Contains(rule.Pattern))
                {
                    result.Warnings.Add($"Duplicate domain pattern found: {rule.Pattern}");
                }
                else
                {
                    seenPatterns.Add(rule.Pattern);
                }

                // Validate regex pattern
                if (!IsValidDomainPattern(rule.Pattern))
                {
                    result.Errors.Add($"Invalid domain pattern: {rule.Pattern}");
                    result.IsValid = false;
                }

                // Validate priority range
                if (rule.Priority < 0 || rule.Priority > 1000)
                {
                    result.Warnings.Add($"Domain rule priority {rule.Priority} is outside recommended range (0-1000) for pattern: {rule.Pattern}");
                }
            }

            // Check for conflicting rules
            var conflicts = FindConflictingRules(rulesList);
            foreach (var conflict in conflicts)
            {
                result.Warnings.Add($"Potential rule conflict detected: {conflict}");
            }

            _logger.LogDebug("Domain rule validation completed: IsValid={IsValid}, Errors={ErrorCount}, Warnings={WarningCount}", 
                result.IsValid, result.Errors.Count, result.Warnings.Count);

            return result;
        }

        #region Private Methods

        /// <summary>
        /// Extracts the domain portion from an email address.
        /// </summary>
        /// <param name="email">The email address</param>
        /// <returns>The domain portion or null if invalid</returns>
        private static string? ExtractDomain(string email)
        {
            if (string.IsNullOrEmpty(email))
                return null;

            var atIndex = email.LastIndexOf('@');
            if (atIndex < 1 || atIndex >= email.Length - 1)
                return null;

            return email.Substring(atIndex + 1).ToLowerInvariant();
        }

        /// <summary>
        /// Validates that a domain pattern is valid.
        /// </summary>
        /// <param name="pattern">The pattern to validate</param>
        /// <returns>True if the pattern is valid</returns>
        private static bool IsValidDomainPattern(string pattern)
        {
            try
            {
                // Convert wildcard pattern to regex and test compilation
                var regexPattern = "^" + Regex.Escape(pattern)
                    .Replace(@"\*", ".*")
                    .Replace(@"\?", ".") + "$";

                var regex = new Regex(regexPattern, RegexOptions.Compiled | RegexOptions.IgnoreCase);
                
                // Test with a simple domain to ensure it's functional
                regex.IsMatch("example.com");
                
                return true;
            }
            catch (Exception)
            {
                return false;
            }
        }

        /// <summary>
        /// Finds wildcard domain overrides that match the specified domain.
        /// </summary>
        /// <param name="domain">The domain to match</param>
        /// <param name="domainOverrides">The domain overrides to search</param>
        /// <returns>The matching override key-value pair or null</returns>
        private static KeyValuePair<string, DomainSpecificPolicy>? FindWildcardDomainOverride(
            string domain, 
            Dictionary<string, DomainSpecificPolicy> domainOverrides)
        {
            foreach (var kvp in domainOverrides)
            {
                if (kvp.Key.Contains('*') || kvp.Key.Contains('?'))
                {
                    var rule = new DomainRule { Pattern = kvp.Key, Enabled = true };
                    if (rule.Matches(domain))
                    {
                        return kvp;
                    }
                }
            }

            return null;
        }

        /// <summary>
        /// Finds potentially conflicting domain rules.
        /// </summary>
        /// <param name="rules">The rules to analyze</param>
        /// <returns>A list of conflict descriptions</returns>
        private static List<string> FindConflictingRules(List<DomainRule> rules)
        {
            var conflicts = new List<string>();
            
            // Simple conflict detection - overlapping patterns with same priority
            for (int i = 0; i < rules.Count; i++)
            {
                for (int j = i + 1; j < rules.Count; j++)
                {
                    var rule1 = rules[i];
                    var rule2 = rules[j];

                    if (rule1.Priority == rule2.Priority && 
                        rule1.Enabled && 
                        rule2.Enabled &&
                        PatternsOverlap(rule1.Pattern, rule2.Pattern))
                    {
                        conflicts.Add($"Rules '{rule1.Pattern}' and '{rule2.Pattern}' have same priority ({rule1.Priority}) and may conflict");
                    }
                }
            }

            return conflicts;
        }

        /// <summary>
        /// Checks if two domain patterns potentially overlap.
        /// </summary>
        /// <param name="pattern1">The first pattern</param>
        /// <param name="pattern2">The second pattern</param>
        /// <returns>True if patterns may overlap</returns>
        private static bool PatternsOverlap(string pattern1, string pattern2)
        {
            // Simple heuristic - if both patterns are wildcards or one contains the other
            if (pattern1.Contains('*') && pattern2.Contains('*'))
                return true;

            if (pattern1.Contains(pattern2, StringComparison.OrdinalIgnoreCase) ||
                pattern2.Contains(pattern1, StringComparison.OrdinalIgnoreCase))
                return true;

            return false;
        }

        #endregion
    }
}