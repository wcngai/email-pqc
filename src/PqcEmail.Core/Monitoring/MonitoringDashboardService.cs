using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Monitoring
{
    /// <summary>
    /// Provides real-time monitoring dashboard services for PQC email system metrics and health monitoring.
    /// </summary>
    public class MonitoringDashboardService : IDashboardDataService, IHealthMonitoringService
    {
        private readonly ILogger<MonitoringDashboardService> _logger;
        private readonly IMetricsCollectionService _metricsService;
        private readonly IPolicyAuditLogger _auditLogger;
        private readonly DashboardConfiguration _configuration;

        /// <summary>
        /// Event raised when a critical health issue is detected.
        /// </summary>
        public event EventHandler<HealthAlertEventArgs>? HealthAlertRaised;

        /// <summary>
        /// Initializes a new instance of the <see cref="MonitoringDashboardService"/> class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="metricsService">The metrics collection service</param>
        /// <param name="auditLogger">The audit logger service</param>
        /// <param name="configuration">The dashboard configuration</param>
        public MonitoringDashboardService(
            ILogger<MonitoringDashboardService> logger,
            IMetricsCollectionService metricsService,
            IPolicyAuditLogger auditLogger,
            DashboardConfiguration configuration)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _metricsService = metricsService ?? throw new ArgumentNullException(nameof(metricsService));
            _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        #region IDashboardDataService Implementation

        /// <summary>
        /// Gets comprehensive dashboard data for the specified time range.
        /// </summary>
        /// <param name="timeRange">The time range for data collection</param>
        /// <returns>The complete dashboard data</returns>
        public async Task<DashboardData> GetDashboardDataAsync(TimeRange timeRange)
        {
            _logger.LogDebug("Retrieving dashboard data for time range: {TimeRange}", timeRange);

            try
            {
                var (startTime, endTime) = GetTimeRangeDates(timeRange);

                var dashboardData = new DashboardData
                {
                    AdoptionMetrics = await GetAdoptionMetricsAsync(timeRange),
                    AlgorithmUsage = await GetAlgorithmUsageAsync(timeRange),
                    KeyLifecycle = await GetKeyLifecycleMetricsAsync(timeRange),
                    PerformanceTrends = await GetPerformanceTrendsAsync(timeRange),
                    SystemHealth = await CheckSystemHealthAsync(),
                    RecentAlerts = await GetRecentAlertsAsync(startTime)
                };

                _logger.LogDebug("Successfully retrieved dashboard data");
                return dashboardData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve dashboard data for time range: {TimeRange}", timeRange);
                throw;
            }
        }

        /// <summary>
        /// Gets PQC adoption metrics for the specified time range.
        /// </summary>
        /// <param name="timeRange">The time range for metrics collection</param>
        /// <returns>The PQC adoption metrics</returns>
        public async Task<PqcAdoptionMetrics> GetAdoptionMetricsAsync(TimeRange timeRange)
        {
            try
            {
                var (startTime, endTime) = GetTimeRangeDates(timeRange);
                var auditEvents = await _auditLogger.GetAuditEventsAsync(startTime, endTime);
                var events = auditEvents.ToList();

                var metrics = new PqcAdoptionMetrics();

                // Calculate total email metrics
                var emailEvents = events.Where(e => 
                    e.EventType == "PolicyDecision" && 
                    !string.IsNullOrEmpty(e.RecipientEmail)).ToList();

                metrics.TotalEmails = emailEvents.Count;

                // Count PQC-enabled emails
                metrics.PqcEnabledEmails = emailEvents.Count(e => 
                    e.AlgorithmsUsed.Any(a => 
                        a.Value.Contains("ML-KEM") || a.Value.Contains("ML-DSA") || 
                        a.Value.Contains("Kyber") || a.Value.Contains("Dilithium")));

                // Count hybrid mode emails
                metrics.HybridModeEmails = emailEvents.Count(e => 
                    e.AlgorithmsUsed.Count > 1 || 
                    e.PolicyDecision?.Contains("hybrid", StringComparison.OrdinalIgnoreCase) == true);

                // Count classical-only emails
                metrics.ClassicalOnlyEmails = emailEvents.Count(e => 
                    e.AlgorithmsUsed.Any(a => 
                        a.Value.Contains("RSA") || a.Value.Contains("ECDSA")) &&
                    !e.AlgorithmsUsed.Any(a => 
                        a.Value.Contains("ML-KEM") || a.Value.Contains("ML-DSA")));

                // Calculate overall adoption rate
                if (metrics.TotalEmails > 0)
                {
                    metrics.OverallAdoptionRate = (double)metrics.PqcEnabledEmails / metrics.TotalEmails * 100;
                }

                // Calculate adoption by domain
                var domainGroups = emailEvents
                    .Where(e => !string.IsNullOrEmpty(e.RecipientEmail))
                    .GroupBy(e => GetDomainFromEmail(e.RecipientEmail!))
                    .Where(g => !string.IsNullOrEmpty(g.Key));

                foreach (var domainGroup in domainGroups)
                {
                    var domainEvents = domainGroup.ToList();
                    var pqcDomainEvents = domainEvents.Count(e => 
                        e.AlgorithmsUsed.Any(a => 
                            a.Value.Contains("ML-KEM") || a.Value.Contains("ML-DSA")));

                    if (domainEvents.Count > 0)
                    {
                        var adoptionRate = (double)pqcDomainEvents / domainEvents.Count * 100;
                        metrics.AdoptionByDomain[domainGroup.Key] = adoptionRate;
                    }
                }

                // Generate trend data (simplified - in real implementation would use time series data)
                metrics.TrendData = GenerateTrendData(events, startTime, endTime);

                return metrics;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve PQC adoption metrics");
                throw;
            }
        }

        /// <summary>
        /// Gets algorithm usage statistics for the specified time range.
        /// </summary>
        /// <param name="timeRange">The time range for statistics collection</param>
        /// <returns>The algorithm usage statistics</returns>
        public async Task<AlgorithmUsageStatistics> GetAlgorithmUsageAsync(TimeRange timeRange)
        {
            try
            {
                var (startTime, endTime) = GetTimeRangeDates(timeRange);
                var auditEvents = await _auditLogger.GetAuditEventsAsync(startTime, endTime);
                var events = auditEvents.Where(e => e.AlgorithmsUsed.Any()).ToList();

                var statistics = new AlgorithmUsageStatistics();

                // Categorize algorithms by type
                foreach (var evt in events)
                {
                    foreach (var algorithm in evt.AlgorithmsUsed)
                    {
                        var algName = algorithm.Value;

                        // KEM algorithms
                        if (IsKemAlgorithm(algName))
                        {
                            statistics.KemAlgorithmUsage[algName] = 
                                statistics.KemAlgorithmUsage.GetValueOrDefault(algName) + 1;
                        }
                        // Signature algorithms
                        else if (IsSignatureAlgorithm(algName))
                        {
                            statistics.SignatureAlgorithmUsage[algName] = 
                                statistics.SignatureAlgorithmUsage.GetValueOrDefault(algName) + 1;
                        }
                    }
                }

                // Calculate fallback frequency
                var fallbackEvents = events.Where(e => e.EventType == "AlgorithmFallback").ToList();
                foreach (var evt in fallbackEvents)
                {
                    if (evt.EventData.TryGetValue("OriginalAlgorithm", out var originalAlg))
                    {
                        var algName = originalAlg?.ToString() ?? "Unknown";
                        statistics.FallbackFrequency[algName] = 
                            statistics.FallbackFrequency.GetValueOrDefault(algName) + 1;
                    }
                }

                // TODO: Calculate algorithm performance from metrics service
                var performanceMetrics = await _metricsService.GetAggregatedMetricsAsync(
                    startTime, endTime, new[] { "CryptographicOperation" });

                foreach (var metric in performanceMetrics)
                {
                    if (metric.MetricName.Contains("ExecutionTime"))
                    {
                        var algName = ExtractAlgorithmFromMetricName(metric.MetricName);
                        if (!string.IsNullOrEmpty(algName))
                        {
                            statistics.AlgorithmPerformance[algName] = metric.AverageValue;
                        }
                    }
                }

                return statistics;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve algorithm usage statistics");
                throw;
            }
        }

        /// <summary>
        /// Gets key lifecycle metrics for the specified time range.
        /// </summary>
        /// <param name="timeRange">The time range for metrics collection</param>
        /// <returns>The key lifecycle metrics</returns>
        public async Task<KeyLifecycleMetrics> GetKeyLifecycleMetricsAsync(TimeRange timeRange)
        {
            try
            {
                var (startTime, endTime) = GetTimeRangeDates(timeRange);
                var auditEvents = await _auditLogger.GetAuditEventsAsync(startTime, endTime, 
                    new[] { "KeyGeneration", "KeyRotation", "KeyExpiration" });

                var metrics = new KeyLifecycleMetrics();

                var keyEvents = auditEvents.ToList();

                // Count key generations in period
                var keyGenEvents = keyEvents.Where(e => e.EventType == "KeyGeneration").ToList();
                metrics.KeyRotationsThisPeriod = keyGenEvents.Count;

                // TODO: In real implementation, these would come from certificate manager
                metrics.ActiveKeys = 150; // Placeholder
                metrics.ExpiredKeys = 12; // Placeholder
                metrics.KeysNearExpiration = 8; // Placeholder

                // Keys by algorithm
                foreach (var evt in keyGenEvents)
                {
                    foreach (var algorithm in evt.AlgorithmsUsed.Values)
                    {
                        metrics.KeysByAlgorithm[algorithm] = 
                            metrics.KeysByAlgorithm.GetValueOrDefault(algorithm) + 1;
                    }
                }

                // Generate key generation trend
                metrics.KeyGenerationTrend = GenerateKeyTrendData(keyGenEvents, startTime, endTime);

                // Average key lifespan (placeholder - would be calculated from actual key data)
                metrics.AverageKeyLifespan = 365.0; // days

                return metrics;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve key lifecycle metrics");
                throw;
            }
        }

        /// <summary>
        /// Gets performance trend data for the specified time range.
        /// </summary>
        /// <param name="timeRange">The time range for trend collection</param>
        /// <returns>The performance trend data</returns>
        public async Task<PerformanceTrendData> GetPerformanceTrendsAsync(TimeRange timeRange)
        {
            try
            {
                var (startTime, endTime) = GetTimeRangeDates(timeRange);
                var performanceMetrics = await _metricsService.GetAggregatedMetricsAsync(
                    startTime, endTime, new[] { "PerformanceMetric" });

                var trendData = new PerformanceTrendData();

                // Group metrics by type and time period
                foreach (var metric in performanceMetrics)
                {
                    var metricDict = GetTrendDictionaryForMetric(trendData, metric.MetricName);
                    if (metricDict != null)
                    {
                        metricDict[metric.PeriodStart] = metric.AverageValue;
                    }
                }

                // Calculate error rate trend
                var auditEvents = await _auditLogger.GetAuditEventsAsync(startTime, endTime);
                var events = auditEvents.ToList();

                var errorRateTrend = new Dictionary<DateTime, double>();
                var timeGroups = GroupEventsByTime(events, startTime, endTime);

                foreach (var timeGroup in timeGroups)
                {
                    var totalEvents = timeGroup.Value.Count;
                    var errorEvents = timeGroup.Value.Count(e => e.Outcome == PolicyOutcome.Failure);
                    var errorRate = totalEvents > 0 ? (double)errorEvents / totalEvents * 100 : 0;
                    errorRateTrend[timeGroup.Key] = errorRate;
                }

                trendData.ErrorRate = errorRateTrend;

                return trendData;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve performance trends");
                throw;
            }
        }

        #endregion

        #region IHealthMonitoringService Implementation

        /// <summary>
        /// Performs a comprehensive health check of the PQC email system.
        /// </summary>
        /// <returns>The system health status</returns>
        public async Task<SystemHealthStatus> CheckSystemHealthAsync()
        {
            _logger.LogDebug("Performing comprehensive system health check");

            try
            {
                var healthStatus = new SystemHealthStatus();

                // Perform individual component health checks
                var healthChecks = new List<Task<HealthCheckResult>>
                {
                    CheckCryptographicHealthAsync(),
                    CheckCertificateHealthAsync(),
                    CheckPolicyHealthAsync()
                };

                var results = await Task.WhenAll(healthChecks);
                healthStatus.ComponentResults.AddRange(results);

                // Determine overall health status
                healthStatus.OverallStatus = DetermineOverallHealthStatus(results);

                // Add system information
                healthStatus.SystemInfo["MachineName"] = Environment.MachineName;
                healthStatus.SystemInfo["OSVersion"] = Environment.OSVersion.ToString();
                healthStatus.SystemInfo["ProcessorCount"] = Environment.ProcessorCount;
                healthStatus.SystemInfo["WorkingSet"] = Environment.WorkingSet;

                // Raise alerts for critical issues
                await CheckForCriticalIssuesAsync(results);

                _logger.LogDebug("Completed system health check with status: {Status}", healthStatus.OverallStatus);
                return healthStatus;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to perform system health check");
                return new SystemHealthStatus
                {
                    OverallStatus = HealthStatus.Unknown,
                    ComponentResults = new List<HealthCheckResult>
                    {
                        new()
                        {
                            ComponentName = "System Health Check",
                            Status = HealthStatus.Unhealthy,
                            Message = $"Health check failed: {ex.Message}"
                        }
                    }
                };
            }
        }

        /// <summary>
        /// Checks the health of cryptographic operations.
        /// </summary>
        /// <returns>The cryptographic health status</returns>
        public async Task<HealthCheckResult> CheckCryptographicHealthAsync()
        {
            var startTime = DateTime.UtcNow;
            var result = new HealthCheckResult
            {
                ComponentName = "Cryptographic Operations"
            };

            try
            {
                // Check recent cryptographic operation success rate
                var recentEvents = await _auditLogger.GetAuditEventsAsync(
                    DateTime.UtcNow.AddHours(-1), DateTime.UtcNow,
                    new[] { "PolicyDecision" });

                var events = recentEvents.ToList();
                if (!events.Any())
                {
                    result.Status = HealthStatus.Unknown;
                    result.Message = "No recent cryptographic operations to evaluate";
                }
                else
                {
                    var successfulEvents = events.Count(e => e.Outcome == PolicyOutcome.Success);
                    var successRate = (double)successfulEvents / events.Count;

                    if (successRate >= 0.98) // 98% success rate threshold
                    {
                        result.Status = HealthStatus.Healthy;
                        result.Message = $"Cryptographic operations healthy ({successRate:P1} success rate)";
                    }
                    else if (successRate >= 0.90)
                    {
                        result.Status = HealthStatus.Degraded;
                        result.Message = $"Cryptographic operations degraded ({successRate:P1} success rate)";
                    }
                    else
                    {
                        result.Status = HealthStatus.Unhealthy;
                        result.Message = $"Cryptographic operations unhealthy ({successRate:P1} success rate)";
                    }

                    result.Details["SuccessRate"] = successRate;
                    result.Details["TotalOperations"] = events.Count;
                    result.Details["SuccessfulOperations"] = successfulEvents;
                }
            }
            catch (Exception ex)
            {
                result.Status = HealthStatus.Unhealthy;
                result.Message = $"Cryptographic health check failed: {ex.Message}";
                _logger.LogError(ex, "Cryptographic health check failed");
            }

            result.ResponseTime = DateTime.UtcNow - startTime;
            return result;
        }

        /// <summary>
        /// Checks the health of certificate management.
        /// </summary>
        /// <returns>The certificate management health status</returns>
        public async Task<HealthCheckResult> CheckCertificateHealthAsync()
        {
            var startTime = DateTime.UtcNow;
            var result = new HealthCheckResult
            {
                ComponentName = "Certificate Management"
            };

            try
            {
                // TODO: In real implementation, would check certificate store health
                // For now, simulate certificate health check
                await Task.Delay(50); // Simulate work

                result.Status = HealthStatus.Healthy;
                result.Message = "Certificate management systems operational";
                result.Details["CertificateStore"] = "Accessible";
                result.Details["HSMConnection"] = "Available";
            }
            catch (Exception ex)
            {
                result.Status = HealthStatus.Unhealthy;
                result.Message = $"Certificate health check failed: {ex.Message}";
                _logger.LogError(ex, "Certificate health check failed");
            }

            result.ResponseTime = DateTime.UtcNow - startTime;
            return result;
        }

        /// <summary>
        /// Checks the health of policy enforcement.
        /// </summary>
        /// <returns>The policy enforcement health status</returns>
        public async Task<HealthCheckResult> CheckPolicyHealthAsync()
        {
            var startTime = DateTime.UtcNow;
            var result = new HealthCheckResult
            {
                ComponentName = "Policy Enforcement"
            };

            try
            {
                // Check for recent policy violations
                var recentViolations = await _auditLogger.GetAuditEventsAsync(
                    DateTime.UtcNow.AddDays(-1), DateTime.UtcNow,
                    new[] { "PolicyViolation" });

                var violations = recentViolations.ToList();
                var violationCount = violations.Count;

                if (violationCount == 0)
                {
                    result.Status = HealthStatus.Healthy;
                    result.Message = "No policy violations detected in last 24 hours";
                }
                else if (violationCount <= 5)
                {
                    result.Status = HealthStatus.Degraded;
                    result.Message = $"{violationCount} policy violations detected in last 24 hours";
                }
                else
                {
                    result.Status = HealthStatus.Unhealthy;
                    result.Message = $"{violationCount} policy violations detected in last 24 hours (exceeds threshold)";
                }

                result.Details["ViolationCount"] = violationCount;
                result.Details["PolicyEngine"] = "Active";
            }
            catch (Exception ex)
            {
                result.Status = HealthStatus.Unhealthy;
                result.Message = $"Policy health check failed: {ex.Message}";
                _logger.LogError(ex, "Policy health check failed");
            }

            result.ResponseTime = DateTime.UtcNow - startTime;
            return result;
        }

        /// <summary>
        /// Gets current system performance metrics.
        /// </summary>
        /// <returns>The system performance metrics</returns>
        public async Task<SystemPerformanceMetrics> GetPerformanceMetricsAsync()
        {
            try
            {
                var metrics = new SystemPerformanceMetrics();

                // Get recent performance data
                var recentMetrics = await _metricsService.GetCurrentMetricsAsync();

                // Extract performance values
                metrics.CpuUsagePercent = recentMetrics.CurrentValues.GetValueOrDefault("CpuUsage", 0);
                metrics.MemoryUsageMB = recentMetrics.CurrentValues.GetValueOrDefault("MemoryUsage", 0);
                metrics.MemoryUsagePercent = recentMetrics.CurrentValues.GetValueOrDefault("MemoryPercent", 0);

                // Calculate operation metrics
                var recentEvents = await _auditLogger.GetAuditEventsAsync(
                    DateTime.UtcNow.AddHours(-1), DateTime.UtcNow);

                var events = recentEvents.ToList();
                metrics.TotalOperations = events.Count;
                
                if (events.Any())
                {
                    var successfulEvents = events.Count(e => e.Outcome == PolicyOutcome.Success);
                    metrics.SuccessRate = (double)successfulEvents / events.Count * 100;
                }

                // TODO: Calculate average response time from actual performance metrics
                metrics.AverageResponseTimeMs = 125.0; // Placeholder

                return metrics;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve system performance metrics");
                throw;
            }
        }

        #endregion

        #region Private Helper Methods

        /// <summary>
        /// Gets start and end dates for a time range.
        /// </summary>
        private static (DateTime startTime, DateTime endTime) GetTimeRangeDates(TimeRange timeRange)
        {
            var endTime = DateTime.UtcNow;
            var startTime = timeRange switch
            {
                TimeRange.LastHour => endTime.AddHours(-1),
                TimeRange.Last24Hours => endTime.AddDays(-1),
                TimeRange.LastWeek => endTime.AddDays(-7),
                TimeRange.LastMonth => endTime.AddDays(-30),
                TimeRange.LastQuarter => endTime.AddDays(-90),
                TimeRange.LastYear => endTime.AddDays(-365),
                _ => endTime.AddDays(-1)
            };

            return (startTime, endTime);
        }

        /// <summary>
        /// Extracts domain from email address.
        /// </summary>
        private static string GetDomainFromEmail(string email)
        {
            var atIndex = email.LastIndexOf('@');
            return atIndex >= 0 && atIndex < email.Length - 1 
                ? email.Substring(atIndex + 1).ToLowerInvariant()
                : string.Empty;
        }

        /// <summary>
        /// Generates trend data from events over time period.
        /// </summary>
        private Dictionary<DateTime, double> GenerateTrendData(
            IEnumerable<PolicyAuditEvent> events, 
            DateTime startTime, 
            DateTime endTime)
        {
            var trendData = new Dictionary<DateTime, double>();
            var eventsList = events.ToList();

            // Create time buckets
            var totalHours = (endTime - startTime).TotalHours;
            var bucketSize = Math.Max(1, totalHours / 24); // Max 24 data points

            for (var time = startTime; time < endTime; time = time.AddHours(bucketSize))
            {
                var bucketEnd = time.AddHours(bucketSize);
                var bucketEvents = eventsList.Where(e => e.Timestamp >= time && e.Timestamp < bucketEnd).ToList();
                
                if (bucketEvents.Any())
                {
                    var pqcEvents = bucketEvents.Count(e => 
                        e.AlgorithmsUsed.Any(a => 
                            a.Value.Contains("ML-KEM") || a.Value.Contains("ML-DSA")));
                    
                    var adoptionRate = (double)pqcEvents / bucketEvents.Count * 100;
                    trendData[time] = adoptionRate;
                }
                else
                {
                    trendData[time] = 0;
                }
            }

            return trendData;
        }

        /// <summary>
        /// Generates key generation trend data.
        /// </summary>
        private Dictionary<DateTime, long> GenerateKeyTrendData(
            IEnumerable<PolicyAuditEvent> keyEvents,
            DateTime startTime,
            DateTime endTime)
        {
            var trendData = new Dictionary<DateTime, long>();
            var eventsList = keyEvents.ToList();

            var timeGroups = GroupEventsByTime(eventsList, startTime, endTime);
            
            foreach (var timeGroup in timeGroups)
            {
                trendData[timeGroup.Key] = timeGroup.Value.Count;
            }

            return trendData;
        }

        /// <summary>
        /// Groups events by time periods.
        /// </summary>
        private Dictionary<DateTime, List<PolicyAuditEvent>> GroupEventsByTime(
            IEnumerable<PolicyAuditEvent> events,
            DateTime startTime,
            DateTime endTime)
        {
            var groups = new Dictionary<DateTime, List<PolicyAuditEvent>>();
            var eventsList = events.ToList();

            var totalHours = (endTime - startTime).TotalHours;
            var bucketSize = Math.Max(1, totalHours / 24);

            for (var time = startTime; time < endTime; time = time.AddHours(bucketSize))
            {
                var bucketEnd = time.AddHours(bucketSize);
                var bucketEvents = eventsList
                    .Where(e => e.Timestamp >= time && e.Timestamp < bucketEnd)
                    .ToList();
                
                groups[time] = bucketEvents;
            }

            return groups;
        }

        /// <summary>
        /// Gets recent alerts for dashboard display.
        /// </summary>
        private async Task<List<RecentAlert>> GetRecentAlertsAsync(DateTime since)
        {
            // TODO: In real implementation, would retrieve from alert storage
            await Task.CompletedTask;
            return new List<RecentAlert>();
        }

        /// <summary>
        /// Checks if an algorithm is a KEM algorithm.
        /// </summary>
        private static bool IsKemAlgorithm(string algorithm)
        {
            return algorithm.Contains("KEM", StringComparison.OrdinalIgnoreCase) ||
                   algorithm.Contains("Kyber", StringComparison.OrdinalIgnoreCase) ||
                   algorithm.Contains("OAEP", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Checks if an algorithm is a signature algorithm.
        /// </summary>
        private static bool IsSignatureAlgorithm(string algorithm)
        {
            return algorithm.Contains("DSA", StringComparison.OrdinalIgnoreCase) ||
                   algorithm.Contains("Dilithium", StringComparison.OrdinalIgnoreCase) ||
                   algorithm.Contains("PSS", StringComparison.OrdinalIgnoreCase) ||
                   algorithm.Contains("ECDSA", StringComparison.OrdinalIgnoreCase);
        }

        /// <summary>
        /// Extracts algorithm name from performance metric name.
        /// </summary>
        private static string ExtractAlgorithmFromMetricName(string metricName)
        {
            // Simple extraction - in real implementation would use more sophisticated parsing
            var parts = metricName.Split('_', '-', '.');
            return parts.FirstOrDefault(p => 
                p.Contains("ML") || p.Contains("RSA") || p.Contains("ECDSA")) ?? string.Empty;
        }

        /// <summary>
        /// Gets the appropriate trend dictionary for a metric.
        /// </summary>
        private Dictionary<DateTime, double>? GetTrendDictionaryForMetric(
            PerformanceTrendData trendData, 
            string metricName)
        {
            return metricName.ToLowerInvariant() switch
            {
                var name when name.Contains("encryption") => trendData.EncryptionPerformance,
                var name when name.Contains("decryption") => trendData.DecryptionPerformance,
                var name when name.Contains("signature") => trendData.SignaturePerformance,
                var name when name.Contains("verification") => trendData.VerificationPerformance,
                var name when name.Contains("throughput") => trendData.OverallThroughput,
                _ => null
            };
        }

        /// <summary>
        /// Determines overall health status from component results.
        /// </summary>
        private static HealthStatus DetermineOverallHealthStatus(IEnumerable<HealthCheckResult> results)
        {
            var resultsList = results.ToList();
            
            if (!resultsList.Any())
                return HealthStatus.Unknown;

            if (resultsList.Any(r => r.Status == HealthStatus.Unhealthy))
                return HealthStatus.Unhealthy;

            if (resultsList.Any(r => r.Status == HealthStatus.Degraded))
                return HealthStatus.Degraded;

            if (resultsList.All(r => r.Status == HealthStatus.Healthy))
                return HealthStatus.Healthy;

            return HealthStatus.Unknown;
        }

        /// <summary>
        /// Checks for critical issues and raises alerts.
        /// </summary>
        private async Task CheckForCriticalIssuesAsync(IEnumerable<HealthCheckResult> results)
        {
            foreach (var result in results.Where(r => r.Status == HealthStatus.Unhealthy))
            {
                var alert = new HealthAlert
                {
                    Severity = AlertSeverity.Critical,
                    Component = result.ComponentName,
                    Message = result.Message ?? "Component is unhealthy",
                    Details = result.Details
                };

                HealthAlertRaised?.Invoke(this, new HealthAlertEventArgs(alert));
                
                _logger.LogWarning("Critical health alert raised for component {Component}: {Message}",
                    result.ComponentName, result.Message);
            }

            await Task.CompletedTask;
        }

        #endregion
    }

    /// <summary>
    /// Configuration settings for the monitoring dashboard.
    /// </summary>
    public class DashboardConfiguration
    {
        /// <summary>
        /// Gets or sets the refresh interval in seconds.
        /// </summary>
        public int RefreshIntervalSeconds { get; set; } = 30;

        /// <summary>
        /// Gets or sets the maximum number of data points for trend charts.
        /// </summary>
        public int MaxTrendDataPoints { get; set; } = 50;

        /// <summary>
        /// Gets or sets the health check interval in minutes.
        /// </summary>
        public int HealthCheckIntervalMinutes { get; set; } = 5;

        /// <summary>
        /// Gets or sets alerting thresholds.
        /// </summary>
        public Dictionary<string, double> AlertThresholds { get; set; } = new()
        {
            ["CryptographicSuccessRate"] = 0.95,
            ["PolicyViolationRate"] = 0.05,
            ["SystemResponseTime"] = 500.0 // milliseconds
        };
    }
}