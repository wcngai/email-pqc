using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Interfaces
{
    /// <summary>
    /// Defines the contract for the PQC email policy engine.
    /// </summary>
    public interface IPolicyEngine
    {
        /// <summary>
        /// Evaluates policies for a specific recipient and returns the effective configuration.
        /// </summary>
        /// <param name="recipientEmail">The recipient's email address</param>
        /// <param name="senderEmail">The sender's email address (optional)</param>
        /// <param name="context">Additional context for policy evaluation</param>
        /// <returns>The policy evaluation result with effective configuration</returns>
        Task<PolicyEvaluationResult> EvaluatePolicyAsync(
            string recipientEmail, 
            string? senderEmail = null, 
            Dictionary<string, object>? context = null);

        /// <summary>
        /// Evaluates policies for multiple recipients and returns the effective configuration.
        /// </summary>
        /// <param name="recipientEmails">The list of recipient email addresses</param>
        /// <param name="senderEmail">The sender's email address (optional)</param>
        /// <param name="context">Additional context for policy evaluation</param>
        /// <returns>The policy evaluation result with effective configuration</returns>
        Task<PolicyEvaluationResult> EvaluatePolicyAsync(
            IEnumerable<string> recipientEmails, 
            string? senderEmail = null, 
            Dictionary<string, object>? context = null);

        /// <summary>
        /// Validates that the specified algorithm is allowed by current policies.
        /// </summary>
        /// <param name="algorithm">The algorithm to validate</param>
        /// <param name="algorithmType">The type of algorithm (KEM, Signature, etc.)</param>
        /// <param name="context">Additional context for validation</param>
        /// <returns>True if the algorithm is allowed, false otherwise</returns>
        Task<bool> ValidateAlgorithmAsync(
            string algorithm, 
            AlgorithmType algorithmType, 
            Dictionary<string, object>? context = null);

        /// <summary>
        /// Gets the current effective policy configuration.
        /// </summary>
        /// <returns>The current policy configuration</returns>
        Task<PqcEmailPolicy> GetEffectivePolicyAsync();

        /// <summary>
        /// Reloads the policy configuration from all sources.
        /// </summary>
        /// <returns>A task representing the asynchronous operation</returns>
        Task ReloadPolicyAsync();

        /// <summary>
        /// Logs an audit event for policy enforcement.
        /// </summary>
        /// <param name="auditEvent">The audit event to log</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task LogAuditEventAsync(PolicyAuditEvent auditEvent);

        /// <summary>
        /// Event raised when policy configuration is updated.
        /// </summary>
        event EventHandler<PolicyUpdatedEventArgs>? PolicyUpdated;

        /// <summary>
        /// Event raised when a policy violation is detected.
        /// </summary>
        event EventHandler<PolicyViolationEventArgs>? PolicyViolationDetected;
    }

    /// <summary>
    /// Defines the contract for policy source providers.
    /// </summary>
    public interface IPolicySourceProvider
    {
        /// <summary>
        /// Gets the policy source type.
        /// </summary>
        PolicySource SourceType { get; }

        /// <summary>
        /// Gets the priority of this policy source (higher number = higher priority).
        /// </summary>
        int Priority { get; }

        /// <summary>
        /// Gets the policy configuration from this source.
        /// </summary>
        /// <returns>The policy configuration or null if not available</returns>
        Task<PqcEmailPolicy?> GetPolicyAsync();

        /// <summary>
        /// Checks if this policy source is available and accessible.
        /// </summary>
        /// <returns>True if the source is available</returns>
        Task<bool> IsAvailableAsync();

        /// <summary>
        /// Event raised when the policy source is updated.
        /// </summary>
        event EventHandler<PolicySourceUpdatedEventArgs>? PolicySourceUpdated;
    }

    /// <summary>
    /// Defines the contract for domain rule evaluation.
    /// </summary>
    public interface IDomainRuleEngine
    {
        /// <summary>
        /// Evaluates domain rules for the specified recipient.
        /// </summary>
        /// <param name="recipientEmail">The recipient's email address</param>
        /// <param name="domainPolicy">The domain policy to evaluate</param>
        /// <returns>The domain rule evaluation result</returns>
        DomainRuleResult EvaluateDomainRules(string recipientEmail, DomainPolicy domainPolicy);

        /// <summary>
        /// Checks if the recipient domain matches any of the specified rules.
        /// </summary>
        /// <param name="recipientEmail">The recipient's email address</param>
        /// <param name="rules">The rules to check</param>
        /// <returns>The matching rule or null if no match</returns>
        DomainRule? FindMatchingRule(string recipientEmail, IEnumerable<DomainRule> rules);

        /// <summary>
        /// Validates and normalizes domain rules.
        /// </summary>
        /// <param name="rules">The rules to validate</param>
        /// <returns>The validation result</returns>
        ValidationResult ValidateDomainRules(IEnumerable<DomainRule> rules);
    }

    /// <summary>
    /// Defines the contract for algorithm enforcement.
    /// </summary>
    public interface IAlgorithmEnforcementEngine
    {
        /// <summary>
        /// Enforces algorithm restrictions based on security policies.
        /// </summary>
        /// <param name="requestedAlgorithm">The requested algorithm</param>
        /// <param name="algorithmType">The type of algorithm</param>
        /// <param name="securityPolicy">The security policy to enforce</param>
        /// <returns>The algorithm enforcement result</returns>
        AlgorithmEnforcementResult EnforceAlgorithmRestrictions(
            string requestedAlgorithm, 
            AlgorithmType algorithmType, 
            SecurityPolicy securityPolicy);

        /// <summary>
        /// Gets the fallback algorithm sequence based on policy and availability.
        /// </summary>
        /// <param name="preferredAlgorithm">The preferred algorithm</param>
        /// <param name="algorithmType">The type of algorithm</param>
        /// <param name="fallbackPolicy">The fallback policy</param>
        /// <param name="availableAlgorithms">The list of available algorithms</param>
        /// <returns>The ordered list of algorithms to try</returns>
        IEnumerable<string> GetFallbackSequence(
            string preferredAlgorithm, 
            AlgorithmType algorithmType, 
            FallbackPolicy fallbackPolicy, 
            IEnumerable<string> availableAlgorithms);

        /// <summary>
        /// Validates that an algorithm meets the minimum security requirements.
        /// </summary>
        /// <param name="algorithm">The algorithm to validate</param>
        /// <param name="algorithmType">The type of algorithm</param>
        /// <param name="minimumSecurityLevel">The minimum required security level</param>
        /// <returns>True if the algorithm meets the requirements</returns>
        bool ValidateAlgorithmSecurity(
            string algorithm, 
            AlgorithmType algorithmType, 
            SecurityLevel minimumSecurityLevel);
    }

    /// <summary>
    /// Defines the contract for policy audit logging.
    /// </summary>
    public interface IPolicyAuditLogger
    {
        /// <summary>
        /// Logs a policy decision event.
        /// </summary>
        /// <param name="auditEvent">The audit event to log</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task LogPolicyDecisionAsync(PolicyAuditEvent auditEvent);

        /// <summary>
        /// Logs a policy violation event.
        /// </summary>
        /// <param name="violation">The policy violation to log</param>
        /// <param name="context">Additional context information</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task LogPolicyViolationAsync(PolicyViolation violation, Dictionary<string, object>? context = null);

        /// <summary>
        /// Logs an algorithm fallback event.
        /// </summary>
        /// <param name="fallbackEvent">The fallback event to log</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task LogFallbackEventAsync(AlgorithmFallbackEvent fallbackEvent);

        /// <summary>
        /// Gets audit events for a specific time period.
        /// </summary>
        /// <param name="startTime">The start time for the query</param>
        /// <param name="endTime">The end time for the query</param>
        /// <param name="eventTypes">Optional filter for event types</param>
        /// <returns>The list of audit events</returns>
        Task<IEnumerable<PolicyAuditEvent>> GetAuditEventsAsync(
            DateTime startTime, 
            DateTime endTime, 
            IEnumerable<string>? eventTypes = null);
    }

    #region Supporting Types

    /// <summary>
    /// Represents the result of domain rule evaluation.
    /// </summary>
    public class DomainRuleResult
    {
        /// <summary>
        /// Gets or sets whether PQC is required for this domain.
        /// </summary>
        public bool RequiresPqc { get; set; }

        /// <summary>
        /// Gets or sets whether encryption is required for this domain.
        /// </summary>
        public bool RequiresEncryption { get; set; }

        /// <summary>
        /// Gets or sets whether classical-only encryption is allowed.
        /// </summary>
        public bool AllowsClassicalOnly { get; set; }

        /// <summary>
        /// Gets or sets the matched domain rules.
        /// </summary>
        public List<DomainRule> MatchedRules { get; set; } = new();

        /// <summary>
        /// Gets or sets any domain-specific policy overrides.
        /// </summary>
        public DomainSpecificPolicy? DomainOverrides { get; set; }
    }

    /// <summary>
    /// Represents the result of algorithm enforcement.
    /// </summary>
    public class AlgorithmEnforcementResult
    {
        /// <summary>
        /// Gets or sets whether the requested algorithm is allowed.
        /// </summary>
        public bool IsAllowed { get; set; }

        /// <summary>
        /// Gets or sets the reason if the algorithm is not allowed.
        /// </summary>
        public string? RejectReason { get; set; }

        /// <summary>
        /// Gets or sets suggested alternative algorithms.
        /// </summary>
        public List<string> SuggestedAlternatives { get; set; } = new();

        /// <summary>
        /// Gets or sets any policy violations detected.
        /// </summary>
        public List<PolicyViolation> Violations { get; set; } = new();
    }

    /// <summary>
    /// Represents a validation result.
    /// </summary>
    public class ValidationResult
    {
        /// <summary>
        /// Gets or sets whether the validation passed.
        /// </summary>
        public bool IsValid { get; set; } = true;

        /// <summary>
        /// Gets or sets validation errors.
        /// </summary>
        public List<string> Errors { get; set; } = new();

        /// <summary>
        /// Gets or sets validation warnings.
        /// </summary>
        public List<string> Warnings { get; set; } = new();
    }

    /// <summary>
    /// Represents a policy audit event.
    /// </summary>
    public class PolicyAuditEvent
    {
        /// <summary>
        /// Gets or sets the event ID.
        /// </summary>
        public Guid EventId { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Gets or sets the event timestamp.
        /// </summary>
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Gets or sets the event type.
        /// </summary>
        public string EventType { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the user or system that triggered the event.
        /// </summary>
        public string? Actor { get; set; }

        /// <summary>
        /// Gets or sets the recipient email address.
        /// </summary>
        public string? RecipientEmail { get; set; }

        /// <summary>
        /// Gets or sets the sender email address.
        /// </summary>
        public string? SenderEmail { get; set; }

        /// <summary>
        /// Gets or sets the policy decision made.
        /// </summary>
        public string? PolicyDecision { get; set; }

        /// <summary>
        /// Gets or sets the algorithms selected or enforced.
        /// </summary>
        public Dictionary<string, string> AlgorithmsUsed { get; set; } = new();

        /// <summary>
        /// Gets or sets additional event data.
        /// </summary>
        public Dictionary<string, object> EventData { get; set; } = new();

        /// <summary>
        /// Gets or sets the outcome of the policy evaluation.
        /// </summary>
        public PolicyOutcome Outcome { get; set; }
    }

    /// <summary>
    /// Represents an algorithm fallback event.
    /// </summary>
    public class AlgorithmFallbackEvent
    {
        /// <summary>
        /// Gets or sets the original algorithm that failed.
        /// </summary>
        public string OriginalAlgorithm { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the fallback algorithm used.
        /// </summary>
        public string FallbackAlgorithm { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the reason for the fallback.
        /// </summary>
        public string Reason { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the fallback attempt number.
        /// </summary>
        public int AttemptNumber { get; set; }

        /// <summary>
        /// Gets or sets whether the fallback was successful.
        /// </summary>
        public bool Successful { get; set; }

        /// <summary>
        /// Gets or sets the recipient email address.
        /// </summary>
        public string? RecipientEmail { get; set; }
    }

    /// <summary>
    /// Event args for policy updated events.
    /// </summary>
    public class PolicyUpdatedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the updated policy configuration.
        /// </summary>
        public PqcEmailPolicy Policy { get; }

        /// <summary>
        /// Gets the source of the policy update.
        /// </summary>
        public PolicySource Source { get; }

        /// <summary>
        /// Initializes a new instance of the PolicyUpdatedEventArgs class.
        /// </summary>
        /// <param name="policy">The updated policy</param>
        /// <param name="source">The source of the update</param>
        public PolicyUpdatedEventArgs(PqcEmailPolicy policy, PolicySource source)
        {
            Policy = policy ?? throw new ArgumentNullException(nameof(policy));
            Source = source;
        }
    }

    /// <summary>
    /// Event args for policy violation events.
    /// </summary>
    public class PolicyViolationEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the policy violation.
        /// </summary>
        public PolicyViolation Violation { get; }

        /// <summary>
        /// Gets additional context information.
        /// </summary>
        public Dictionary<string, object> Context { get; }

        /// <summary>
        /// Initializes a new instance of the PolicyViolationEventArgs class.
        /// </summary>
        /// <param name="violation">The policy violation</param>
        /// <param name="context">Additional context</param>
        public PolicyViolationEventArgs(PolicyViolation violation, Dictionary<string, object>? context = null)
        {
            Violation = violation ?? throw new ArgumentNullException(nameof(violation));
            Context = context ?? new Dictionary<string, object>();
        }
    }

    /// <summary>
    /// Event args for policy source updated events.
    /// </summary>
    public class PolicySourceUpdatedEventArgs : EventArgs
    {
        /// <summary>
        /// Gets the policy source type.
        /// </summary>
        public PolicySource SourceType { get; }

        /// <summary>
        /// Gets the updated policy configuration.
        /// </summary>
        public PqcEmailPolicy? Policy { get; }

        /// <summary>
        /// Initializes a new instance of the PolicySourceUpdatedEventArgs class.
        /// </summary>
        /// <param name="sourceType">The source type</param>
        /// <param name="policy">The updated policy</param>
        public PolicySourceUpdatedEventArgs(PolicySource sourceType, PqcEmailPolicy? policy)
        {
            SourceType = sourceType;
            Policy = policy;
        }
    }

    /// <summary>
    /// Defines algorithm types for policy enforcement.
    /// </summary>
    public enum AlgorithmType
    {
        Kem,
        Signature,
        Symmetric,
        Hash
    }

    /// <summary>
    /// Defines policy evaluation outcomes.
    /// </summary>
    public enum PolicyOutcome
    {
        Success,
        Failure,
        Fallback,
        Violation
    }

    #endregion
}