using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Interfaces
{
    /// <summary>
    /// Defines the contract for SIEM integration services.
    /// </summary>
    public interface ISiemIntegrationService
    {
        /// <summary>
        /// Sends an audit event to the configured SIEM system.
        /// </summary>
        /// <param name="auditEvent">The audit event to send</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task SendAuditEventAsync(PolicyAuditEvent auditEvent);

        /// <summary>
        /// Sends a batch of audit events to the configured SIEM system.
        /// </summary>
        /// <param name="auditEvents">The audit events to send</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task SendAuditEventsBatchAsync(IEnumerable<PolicyAuditEvent> auditEvents);

        /// <summary>
        /// Tests the connection to the SIEM system.
        /// </summary>
        /// <returns>True if the connection is successful</returns>
        Task<bool> TestConnectionAsync();
    }

    /// <summary>
    /// Defines the contract for metrics collection services.
    /// </summary>
    public interface IMetricsCollectionService
    {
        /// <summary>
        /// Records a cryptographic operation metric.
        /// </summary>
        /// <param name="metric">The metric to record</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task RecordCryptographicOperationAsync(CryptographicOperationMetric metric);

        /// <summary>
        /// Records a performance metric.
        /// </summary>
        /// <param name="metric">The metric to record</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task RecordPerformanceMetricAsync(PerformanceMetric metric);

        /// <summary>
        /// Records a policy enforcement metric.
        /// </summary>
        /// <param name="metric">The metric to record</param>
        /// <returns>A task representing the asynchronous operation</returns>
        Task RecordPolicyEnforcementMetricAsync(PolicyEnforcementMetric metric);

        /// <summary>
        /// Gets aggregated metrics for a specific time period.
        /// </summary>
        /// <param name="startTime">The start time</param>
        /// <param name="endTime">The end time</param>
        /// <param name="metricTypes">Optional filter for metric types</param>
        /// <returns>The aggregated metrics</returns>
        Task<IEnumerable<AggregatedMetric>> GetAggregatedMetricsAsync(
            DateTime startTime, 
            DateTime endTime, 
            IEnumerable<string>? metricTypes = null);

        /// <summary>
        /// Gets real-time metrics for dashboard display.
        /// </summary>
        /// <returns>The current metrics snapshot</returns>
        Task<MetricsSnapshot> GetCurrentMetricsAsync();
    }

    /// <summary>
    /// Defines the contract for compliance reporting services.
    /// </summary>
    public interface IComplianceReportingService
    {
        /// <summary>
        /// Generates a SOX compliance report.
        /// </summary>
        /// <param name="reportPeriod">The reporting period</param>
        /// <returns>The generated report</returns>
        Task<ComplianceReport> GenerateSoxReportAsync(ReportingPeriod reportPeriod);

        /// <summary>
        /// Generates a GDPR compliance report.
        /// </summary>
        /// <param name="reportPeriod">The reporting period</param>
        /// <returns>The generated report</returns>
        Task<ComplianceReport> GenerateGdprReportAsync(ReportingPeriod reportPeriod);

        /// <summary>
        /// Generates an FFIEC compliance report.
        /// </summary>
        /// <param name="reportPeriod">The reporting period</param>
        /// <returns>The generated report</returns>
        Task<ComplianceReport> GenerateFfiecReportAsync(ReportingPeriod reportPeriod);

        /// <summary>
        /// Gets available compliance reports for a time period.
        /// </summary>
        /// <param name="startDate">The start date</param>
        /// <param name="endDate">The end date</param>
        /// <returns>The list of available reports</returns>
        Task<IEnumerable<ComplianceReportSummary>> GetAvailableReportsAsync(DateTime startDate, DateTime endDate);

        /// <summary>
        /// Exports a compliance report in the specified format.
        /// </summary>
        /// <param name="reportId">The report identifier</param>
        /// <param name="format">The export format</param>
        /// <returns>The exported report data</returns>
        Task<byte[]> ExportReportAsync(Guid reportId, ExportFormat format);
    }

    /// <summary>
    /// Defines the contract for health monitoring services.
    /// </summary>
    public interface IHealthMonitoringService
    {
        /// <summary>
        /// Performs a comprehensive health check of the PQC email system.
        /// </summary>
        /// <returns>The health check result</returns>
        Task<SystemHealthStatus> CheckSystemHealthAsync();

        /// <summary>
        /// Checks the health of cryptographic operations.
        /// </summary>
        /// <returns>The cryptographic health status</returns>
        Task<HealthCheckResult> CheckCryptographicHealthAsync();

        /// <summary>
        /// Checks the health of certificate management.
        /// </summary>
        /// <returns>The certificate management health status</returns>
        Task<HealthCheckResult> CheckCertificateHealthAsync();

        /// <summary>
        /// Checks the health of policy enforcement.
        /// </summary>
        /// <returns>The policy enforcement health status</returns>
        Task<HealthCheckResult> CheckPolicyHealthAsync();

        /// <summary>
        /// Gets the current system performance metrics.
        /// </summary>
        /// <returns>The performance metrics</returns>
        Task<SystemPerformanceMetrics> GetPerformanceMetricsAsync();

        /// <summary>
        /// Event raised when a critical health issue is detected.
        /// </summary>
        event EventHandler<HealthAlertEventArgs>? HealthAlertRaised;
    }

    /// <summary>
    /// Defines the contract for dashboard data services.
    /// </summary>
    public interface IDashboardDataService
    {
        /// <summary>
        /// Gets dashboard data for the specified time period.
        /// </summary>
        /// <param name="timeRange">The time range for data</param>
        /// <returns>The dashboard data</returns>
        Task<DashboardData> GetDashboardDataAsync(TimeRange timeRange);

        /// <summary>
        /// Gets PQC adoption metrics.
        /// </summary>
        /// <param name="timeRange">The time range for metrics</param>
        /// <returns>The adoption metrics</returns>
        Task<PqcAdoptionMetrics> GetAdoptionMetricsAsync(TimeRange timeRange);

        /// <summary>
        /// Gets algorithm usage statistics.
        /// </summary>
        /// <param name="timeRange">The time range for statistics</param>
        /// <returns>The algorithm usage statistics</returns>
        Task<AlgorithmUsageStatistics> GetAlgorithmUsageAsync(TimeRange timeRange);

        /// <summary>
        /// Gets key lifecycle metrics.
        /// </summary>
        /// <param name="timeRange">The time range for metrics</param>
        /// <returns>The key lifecycle metrics</returns>
        Task<KeyLifecycleMetrics> GetKeyLifecycleMetricsAsync(TimeRange timeRange);

        /// <summary>
        /// Gets performance trend data.
        /// </summary>
        /// <param name="timeRange">The time range for trends</param>
        /// <returns>The performance trend data</returns>
        Task<PerformanceTrendData> GetPerformanceTrendsAsync(TimeRange timeRange);
    }

    #region Supporting Types

    /// <summary>
    /// Represents a cryptographic operation metric.
    /// </summary>
    public class CryptographicOperationMetric
    {
        public Guid MetricId { get; set; } = Guid.NewGuid();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string OperationType { get; set; } = string.Empty;
        public string Algorithm { get; set; } = string.Empty;
        public long ExecutionTimeMs { get; set; }
        public bool Success { get; set; }
        public string? ErrorDetails { get; set; }
        public Dictionary<string, object> AdditionalData { get; set; } = new();
    }

    /// <summary>
    /// Represents a performance metric.
    /// </summary>
    public class PerformanceMetric
    {
        public Guid MetricId { get; set; } = Guid.NewGuid();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string MetricName { get; set; } = string.Empty;
        public double Value { get; set; }
        public string Unit { get; set; } = string.Empty;
        public Dictionary<string, string> Tags { get; set; } = new();
    }

    /// <summary>
    /// Represents a policy enforcement metric.
    /// </summary>
    public class PolicyEnforcementMetric
    {
        public Guid MetricId { get; set; } = Guid.NewGuid();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public string PolicyType { get; set; } = string.Empty;
        public string Recipient { get; set; } = string.Empty;
        public PolicyOutcome Outcome { get; set; }
        public string? AlgorithmsApplied { get; set; }
        public Dictionary<string, object> Context { get; set; } = new();
    }

    /// <summary>
    /// Represents an aggregated metric.
    /// </summary>
    public class AggregatedMetric
    {
        public string MetricName { get; set; } = string.Empty;
        public DateTime PeriodStart { get; set; }
        public DateTime PeriodEnd { get; set; }
        public double MinValue { get; set; }
        public double MaxValue { get; set; }
        public double AverageValue { get; set; }
        public double SumValue { get; set; }
        public int Count { get; set; }
        public Dictionary<string, object> Breakdown { get; set; } = new();
    }

    /// <summary>
    /// Represents a current metrics snapshot.
    /// </summary>
    public class MetricsSnapshot
    {
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public Dictionary<string, double> CurrentValues { get; set; } = new();
        public Dictionary<string, object> AdditionalMetrics { get; set; } = new();
    }

    /// <summary>
    /// Represents system health status.
    /// </summary>
    public class SystemHealthStatus
    {
        public HealthStatus OverallStatus { get; set; }
        public List<HealthCheckResult> ComponentResults { get; set; } = new();
        public DateTime LastChecked { get; set; } = DateTime.UtcNow;
        public Dictionary<string, object> SystemInfo { get; set; } = new();
    }

    /// <summary>
    /// Represents a health check result.
    /// </summary>
    public class HealthCheckResult
    {
        public string ComponentName { get; set; } = string.Empty;
        public HealthStatus Status { get; set; }
        public string? Message { get; set; }
        public TimeSpan ResponseTime { get; set; }
        public Dictionary<string, object> Details { get; set; } = new();
    }

    /// <summary>
    /// Represents system performance metrics.
    /// </summary>
    public class SystemPerformanceMetrics
    {
        public double CpuUsagePercent { get; set; }
        public double MemoryUsageMB { get; set; }
        public double MemoryUsagePercent { get; set; }
        public long TotalOperations { get; set; }
        public double SuccessRate { get; set; }
        public double AverageResponseTimeMs { get; set; }
        public Dictionary<string, double> AlgorithmPerformance { get; set; } = new();
    }

    /// <summary>
    /// Event args for health alerts.
    /// </summary>
    public class HealthAlertEventArgs : EventArgs
    {
        public HealthAlert Alert { get; }

        public HealthAlertEventArgs(HealthAlert alert)
        {
            Alert = alert ?? throw new ArgumentNullException(nameof(alert));
        }
    }

    /// <summary>
    /// Represents a health alert.
    /// </summary>
    public class HealthAlert
    {
        public Guid AlertId { get; set; } = Guid.NewGuid();
        public DateTime Timestamp { get; set; } = DateTime.UtcNow;
        public AlertSeverity Severity { get; set; }
        public string Component { get; set; } = string.Empty;
        public string Message { get; set; } = string.Empty;
        public Dictionary<string, object> Details { get; set; } = new();
    }

    /// <summary>
    /// Defines health status levels.
    /// </summary>
    public enum HealthStatus
    {
        Healthy,
        Degraded,
        Unhealthy,
        Unknown
    }

    /// <summary>
    /// Defines alert severity levels.
    /// </summary>
    public enum AlertSeverity
    {
        Info,
        Warning,
        Critical
    }

    /// <summary>
    /// Defines time ranges for data queries.
    /// </summary>
    public enum TimeRange
    {
        LastHour,
        Last24Hours,
        LastWeek,
        LastMonth,
        LastQuarter,
        LastYear,
        Custom
    }

    #endregion
}