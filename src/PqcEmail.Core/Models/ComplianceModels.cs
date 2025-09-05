using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace PqcEmail.Core.Models
{
    /// <summary>
    /// Represents a compliance report.
    /// </summary>
    public class ComplianceReport
    {
        /// <summary>
        /// Gets or sets the unique report identifier.
        /// </summary>
        public Guid ReportId { get; set; } = Guid.NewGuid();

        /// <summary>
        /// Gets or sets the report type (SOX, GDPR, FFIEC, etc.).
        /// </summary>
        public ComplianceStandard Standard { get; set; }

        /// <summary>
        /// Gets or sets the reporting period.
        /// </summary>
        public ReportingPeriod Period { get; set; } = new();

        /// <summary>
        /// Gets or sets the report generation timestamp.
        /// </summary>
        public DateTime GeneratedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Gets or sets the user who generated the report.
        /// </summary>
        public string GeneratedBy { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the report title.
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the executive summary.
        /// </summary>
        public string ExecutiveSummary { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the overall compliance status.
        /// </summary>
        public ComplianceStatus Status { get; set; }

        /// <summary>
        /// Gets or sets the detailed compliance sections.
        /// </summary>
        public List<ComplianceSection> Sections { get; set; } = new();

        /// <summary>
        /// Gets or sets the findings and recommendations.
        /// </summary>
        public List<ComplianceFinding> Findings { get; set; } = new();

        /// <summary>
        /// Gets or sets the metrics and statistics.
        /// </summary>
        public ComplianceMetrics Metrics { get; set; } = new();

        /// <summary>
        /// Gets or sets any exceptions or deviations.
        /// </summary>
        public List<ComplianceException> Exceptions { get; set; } = new();

        /// <summary>
        /// Gets or sets the audit evidence references.
        /// </summary>
        public List<AuditEvidence> Evidence { get; set; } = new();

        /// <summary>
        /// Gets or sets additional metadata.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    /// <summary>
    /// Represents a compliance report summary.
    /// </summary>
    public class ComplianceReportSummary
    {
        public Guid ReportId { get; set; }
        public ComplianceStandard Standard { get; set; }
        public DateTime StartDate { get; set; }
        public DateTime EndDate { get; set; }
        public DateTime GeneratedAt { get; set; }
        public string GeneratedBy { get; set; } = string.Empty;
        public ComplianceStatus Status { get; set; }
        public int FindingsCount { get; set; }
        public int CriticalIssues { get; set; }
        public double ComplianceScore { get; set; }
    }

    /// <summary>
    /// Represents a reporting period.
    /// </summary>
    public class ReportingPeriod
    {
        /// <summary>
        /// Gets or sets the start date of the reporting period.
        /// </summary>
        [Required]
        public DateTime StartDate { get; set; }

        /// <summary>
        /// Gets or sets the end date of the reporting period.
        /// </summary>
        [Required]
        public DateTime EndDate { get; set; }

        /// <summary>
        /// Gets or sets the period type.
        /// </summary>
        public PeriodType Type { get; set; }

        /// <summary>
        /// Gets or sets a description of the period.
        /// </summary>
        public string? Description { get; set; }

        /// <summary>
        /// Validates the reporting period.
        /// </summary>
        /// <returns>True if valid</returns>
        public bool IsValid()
        {
            return StartDate < EndDate && 
                   StartDate != default && 
                   EndDate != default &&
                   EndDate <= DateTime.UtcNow;
        }

        /// <summary>
        /// Gets the duration of the reporting period.
        /// </summary>
        /// <returns>The duration</returns>
        public TimeSpan Duration => EndDate - StartDate;
    }

    /// <summary>
    /// Represents a compliance section within a report.
    /// </summary>
    public class ComplianceSection
    {
        /// <summary>
        /// Gets or sets the section identifier.
        /// </summary>
        public string SectionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the section title.
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the section description.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the compliance requirements addressed.
        /// </summary>
        public List<string> Requirements { get; set; } = new();

        /// <summary>
        /// Gets or sets the section compliance status.
        /// </summary>
        public ComplianceStatus Status { get; set; }

        /// <summary>
        /// Gets or sets the detailed findings for this section.
        /// </summary>
        public string Details { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the supporting evidence.
        /// </summary>
        public List<string> EvidenceReferences { get; set; } = new();

        /// <summary>
        /// Gets or sets any control gaps or weaknesses.
        /// </summary>
        public List<string> Gaps { get; set; } = new();

        /// <summary>
        /// Gets or sets recommendations for improvement.
        /// </summary>
        public List<string> Recommendations { get; set; } = new();
    }

    /// <summary>
    /// Represents a compliance finding.
    /// </summary>
    public class ComplianceFinding
    {
        /// <summary>
        /// Gets or sets the finding identifier.
        /// </summary>
        public string FindingId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the finding type.
        /// </summary>
        public FindingType Type { get; set; }

        /// <summary>
        /// Gets or sets the severity level.
        /// </summary>
        public FindingSeverity Severity { get; set; }

        /// <summary>
        /// Gets or sets the finding title.
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the detailed description.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the compliance requirement affected.
        /// </summary>
        public string Requirement { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the business impact.
        /// </summary>
        public string Impact { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the recommended remediation.
        /// </summary>
        public string Recommendation { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the target resolution date.
        /// </summary>
        public DateTime? TargetDate { get; set; }

        /// <summary>
        /// Gets or sets the responsible party.
        /// </summary>
        public string? AssignedTo { get; set; }

        /// <summary>
        /// Gets or sets supporting audit evidence.
        /// </summary>
        public List<string> EvidenceReferences { get; set; } = new();

        /// <summary>
        /// Gets or sets the current remediation status.
        /// </summary>
        public RemediationStatus Status { get; set; }
    }

    /// <summary>
    /// Represents compliance metrics and statistics.
    /// </summary>
    public class ComplianceMetrics
    {
        /// <summary>
        /// Gets or sets the total number of audit events reviewed.
        /// </summary>
        public long TotalAuditEvents { get; set; }

        /// <summary>
        /// Gets or sets the number of policy decisions made.
        /// </summary>
        public long PolicyDecisions { get; set; }

        /// <summary>
        /// Gets or sets the number of policy violations detected.
        /// </summary>
        public long PolicyViolations { get; set; }

        /// <summary>
        /// Gets or sets the number of algorithm fallback events.
        /// </summary>
        public long FallbackEvents { get; set; }

        /// <summary>
        /// Gets or sets the number of successful cryptographic operations.
        /// </summary>
        public long SuccessfulOperations { get; set; }

        /// <summary>
        /// Gets or sets the number of failed operations.
        /// </summary>
        public long FailedOperations { get; set; }

        /// <summary>
        /// Gets or sets the percentage of PQC-enabled communications.
        /// </summary>
        public double PqcAdoptionRate { get; set; }

        /// <summary>
        /// Gets or sets the overall compliance score (0-100).
        /// </summary>
        public double ComplianceScore { get; set; }

        /// <summary>
        /// Gets or sets algorithm usage statistics.
        /// </summary>
        public Dictionary<string, long> AlgorithmUsage { get; set; } = new();

        /// <summary>
        /// Gets or sets risk-based metrics.
        /// </summary>
        public Dictionary<string, double> RiskMetrics { get; set; } = new();

        /// <summary>
        /// Gets or sets performance metrics.
        /// </summary>
        public Dictionary<string, double> PerformanceMetrics { get; set; } = new();
    }

    /// <summary>
    /// Represents a compliance exception or deviation.
    /// </summary>
    public class ComplianceException
    {
        /// <summary>
        /// Gets or sets the exception identifier.
        /// </summary>
        public string ExceptionId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the exception type.
        /// </summary>
        public ExceptionType Type { get; set; }

        /// <summary>
        /// Gets or sets the title of the exception.
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the detailed description.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the business justification.
        /// </summary>
        public string Justification { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the approval authority.
        /// </summary>
        public string ApprovedBy { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the approval date.
        /// </summary>
        public DateTime ApprovedDate { get; set; }

        /// <summary>
        /// Gets or sets the expiration date of the exception.
        /// </summary>
        public DateTime? ExpirationDate { get; set; }

        /// <summary>
        /// Gets or sets compensating controls in place.
        /// </summary>
        public List<string> CompensatingControls { get; set; } = new();

        /// <summary>
        /// Gets or sets the risk assessment.
        /// </summary>
        public string RiskAssessment { get; set; } = string.Empty;
    }

    /// <summary>
    /// Represents audit evidence supporting compliance.
    /// </summary>
    public class AuditEvidence
    {
        /// <summary>
        /// Gets or sets the evidence identifier.
        /// </summary>
        public string EvidenceId { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the evidence type.
        /// </summary>
        public EvidenceType Type { get; set; }

        /// <summary>
        /// Gets or sets the evidence title.
        /// </summary>
        public string Title { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the evidence description.
        /// </summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the source system or process.
        /// </summary>
        public string Source { get; set; } = string.Empty;

        /// <summary>
        /// Gets or sets the collection date and time.
        /// </summary>
        public DateTime CollectedAt { get; set; } = DateTime.UtcNow;

        /// <summary>
        /// Gets or sets the file path or reference.
        /// </summary>
        public string? FilePath { get; set; }

        /// <summary>
        /// Gets or sets the hash for integrity verification.
        /// </summary>
        public string? Hash { get; set; }

        /// <summary>
        /// Gets or sets related audit event IDs.
        /// </summary>
        public List<Guid> RelatedEventIds { get; set; } = new();

        /// <summary>
        /// Gets or sets additional metadata.
        /// </summary>
        public Dictionary<string, object> Metadata { get; set; } = new();
    }

    #region Dashboard Models

    /// <summary>
    /// Represents dashboard data for the monitoring interface.
    /// </summary>
    public class DashboardData
    {
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public PqcAdoptionMetrics AdoptionMetrics { get; set; } = new();
        public AlgorithmUsageStatistics AlgorithmUsage { get; set; } = new();
        public KeyLifecycleMetrics KeyLifecycle { get; set; } = new();
        public PerformanceTrendData PerformanceTrends { get; set; } = new();
        public SystemHealthStatus SystemHealth { get; set; } = new();
        public List<RecentAlert> RecentAlerts { get; set; } = new();
    }

    /// <summary>
    /// Represents PQC adoption metrics.
    /// </summary>
    public class PqcAdoptionMetrics
    {
        public double OverallAdoptionRate { get; set; }
        public long TotalEmails { get; set; }
        public long PqcEnabledEmails { get; set; }
        public long HybridModeEmails { get; set; }
        public long ClassicalOnlyEmails { get; set; }
        public Dictionary<string, double> AdoptionByDomain { get; set; } = new();
        public Dictionary<DateTime, double> TrendData { get; set; } = new();
    }

    /// <summary>
    /// Represents algorithm usage statistics.
    /// </summary>
    public class AlgorithmUsageStatistics
    {
        public Dictionary<string, long> KemAlgorithmUsage { get; set; } = new();
        public Dictionary<string, long> SignatureAlgorithmUsage { get; set; } = new();
        public Dictionary<string, double> AlgorithmPerformance { get; set; } = new();
        public Dictionary<string, long> FallbackFrequency { get; set; } = new();
        public DateTime LastUpdated { get; set; } = DateTime.UtcNow;
    }

    /// <summary>
    /// Represents key lifecycle metrics.
    /// </summary>
    public class KeyLifecycleMetrics
    {
        public long ActiveKeys { get; set; }
        public long ExpiredKeys { get; set; }
        public long KeysNearExpiration { get; set; }
        public long KeyRotationsThisPeriod { get; set; }
        public Dictionary<string, long> KeysByAlgorithm { get; set; } = new();
        public Dictionary<DateTime, long> KeyGenerationTrend { get; set; } = new();
        public double AverageKeyLifespan { get; set; }
    }

    /// <summary>
    /// Represents performance trend data.
    /// </summary>
    public class PerformanceTrendData
    {
        public Dictionary<DateTime, double> EncryptionPerformance { get; set; } = new();
        public Dictionary<DateTime, double> DecryptionPerformance { get; set; } = new();
        public Dictionary<DateTime, double> SignaturePerformance { get; set; } = new();
        public Dictionary<DateTime, double> VerificationPerformance { get; set; } = new();
        public Dictionary<DateTime, double> OverallThroughput { get; set; } = new();
        public Dictionary<DateTime, double> ErrorRate { get; set; } = new();
    }

    /// <summary>
    /// Represents a recent alert for dashboard display.
    /// </summary>
    public class RecentAlert
    {
        public Guid AlertId { get; set; }
        public DateTime Timestamp { get; set; }
        public AlertSeverity Severity { get; set; }
        public string Component { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public bool Acknowledged { get; set; }
        public string? AcknowledgedBy { get; set; }
    }

    #endregion

    #region Enums

    /// <summary>
    /// Defines compliance standards.
    /// </summary>
    public enum ComplianceStandard
    {
        SOX,        // Sarbanes-Oxley Act
        GDPR,       // General Data Protection Regulation
        FFIEC,      // Federal Financial Institutions Examination Council
        HIPAA,      // Health Insurance Portability and Accountability Act
        PCI_DSS,    // Payment Card Industry Data Security Standard
        ISO27001,   // Information Security Management System
        NIST,       // National Institute of Standards and Technology
        Custom
    }

    /// <summary>
    /// Defines compliance status levels.
    /// </summary>
    public enum ComplianceStatus
    {
        Compliant,
        NonCompliant,
        PartiallyCompliant,
        NotApplicable,
        UnderReview
    }

    /// <summary>
    /// Defines reporting period types.
    /// </summary>
    public enum PeriodType
    {
        Daily,
        Weekly,
        Monthly,
        Quarterly,
        Annual,
        Custom
    }

    /// <summary>
    /// Defines finding types.
    /// </summary>
    public enum FindingType
    {
        ControlGap,
        PolicyViolation,
        ProcessDeficiency,
        TechnicalIssue,
        DocumentationGap,
        TrainingGap,
        BestPractice
    }

    /// <summary>
    /// Defines finding severity levels.
    /// </summary>
    public enum FindingSeverity
    {
        Low,
        Medium,
        High,
        Critical
    }

    /// <summary>
    /// Defines remediation status.
    /// </summary>
    public enum RemediationStatus
    {
        Open,
        InProgress,
        Resolved,
        Closed,
        Deferred,
        NotPlanned
    }

    /// <summary>
    /// Defines exception types.
    /// </summary>
    public enum ExceptionType
    {
        PolicyException,
        TechnicalLimitation,
        BusinessRequirement,
        TemporaryWorkaround,
        LegacySystem
    }

    /// <summary>
    /// Defines evidence types.
    /// </summary>
    public enum EvidenceType
    {
        AuditLog,
        Configuration,
        Policy,
        Procedure,
        Screenshot,
        Report,
        Certificate,
        TestResult
    }

    /// <summary>
    /// Defines export formats for compliance reports.
    /// </summary>
    public enum ExportFormat
    {
        PDF,
        Excel,
        CSV,
        JSON,
        XML,
        HTML
    }

    #endregion
}