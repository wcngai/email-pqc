using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Monitoring
{
    /// <summary>
    /// Provides metrics collection and aggregation services for PQC email system monitoring.
    /// </summary>
    public class MetricsCollectionService : IMetricsCollectionService, IDisposable
    {
        private readonly ILogger<MetricsCollectionService> _logger;
        private readonly MetricsConfiguration _configuration;
        private readonly ConcurrentQueue<CryptographicOperationMetric> _cryptographicMetrics;
        private readonly ConcurrentQueue<PerformanceMetric> _performanceMetrics;
        private readonly ConcurrentQueue<PolicyEnforcementMetric> _policyMetrics;
        private readonly Timer _aggregationTimer;
        private readonly object _metricsLock = new object();
        private bool _disposed;

        // Performance counters
        private readonly PerformanceCounter _cpuCounter;
        private readonly PerformanceCounter _memoryCounter;
        private readonly Process _currentProcess;

        /// <summary>
        /// Initializes a new instance of the <see cref="MetricsCollectionService"/> class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="configuration">The metrics configuration</param>
        public MetricsCollectionService(
            ILogger<MetricsCollectionService> logger,
            MetricsConfiguration configuration)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

            _cryptographicMetrics = new ConcurrentQueue<CryptographicOperationMetric>();
            _performanceMetrics = new ConcurrentQueue<PerformanceMetric>();
            _policyMetrics = new ConcurrentQueue<PolicyEnforcementMetric>();

            // Initialize performance counters
            _cpuCounter = new PerformanceCounter("Processor", "% Processor Time", "_Total");
            _memoryCounter = new PerformanceCounter("Memory", "Available MBytes");
            _currentProcess = Process.GetCurrentProcess();

            // Start aggregation timer
            _aggregationTimer = new Timer(
                AggregateMetrics,
                null,
                TimeSpan.FromSeconds(_configuration.AggregationIntervalSeconds),
                TimeSpan.FromSeconds(_configuration.AggregationIntervalSeconds));

            _logger.LogInformation("MetricsCollectionService initialized with aggregation interval: {Interval}s",
                _configuration.AggregationIntervalSeconds);
        }

        /// <summary>
        /// Records a cryptographic operation metric.
        /// </summary>
        /// <param name="metric">The metric to record</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task RecordCryptographicOperationAsync(CryptographicOperationMetric metric)
        {
            if (metric == null)
                throw new ArgumentNullException(nameof(metric));

            try
            {
                // Enrich metric with additional system information
                metric.AdditionalData["MachineName"] = Environment.MachineName;
                metric.AdditionalData["ProcessId"] = Environment.ProcessId;
                metric.AdditionalData["ThreadId"] = Thread.CurrentThread.ManagedThreadId;

                _cryptographicMetrics.Enqueue(metric);

                // Also record as performance metric for trend analysis
                await RecordPerformanceMetricAsync(new PerformanceMetric
                {
                    MetricName = $"CryptographicOperation_{metric.OperationType}_{metric.Algorithm}_ExecutionTime",
                    Value = metric.ExecutionTimeMs,
                    Unit = "milliseconds",
                    Tags = new Dictionary<string, string>
                    {
                        ["OperationType"] = metric.OperationType,
                        ["Algorithm"] = metric.Algorithm,
                        ["Success"] = metric.Success.ToString()
                    }
                });

                _logger.LogTrace("Recorded cryptographic operation metric: {OperationType} {Algorithm} {Duration}ms {Success}",
                    metric.OperationType, metric.Algorithm, metric.ExecutionTimeMs, metric.Success);

                // Maintain queue size limits
                await EnforceQueueLimitsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to record cryptographic operation metric");
            }
        }

        /// <summary>
        /// Records a performance metric.
        /// </summary>
        /// <param name="metric">The metric to record</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task RecordPerformanceMetricAsync(PerformanceMetric metric)
        {
            if (metric == null)
                throw new ArgumentNullException(nameof(metric));

            try
            {
                _performanceMetrics.Enqueue(metric);

                _logger.LogTrace("Recorded performance metric: {MetricName} = {Value} {Unit}",
                    metric.MetricName, metric.Value, metric.Unit);

                // Maintain queue size limits
                await EnforceQueueLimitsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to record performance metric");
            }
        }

        /// <summary>
        /// Records a policy enforcement metric.
        /// </summary>
        /// <param name="metric">The metric to record</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task RecordPolicyEnforcementMetricAsync(PolicyEnforcementMetric metric)
        {
            if (metric == null)
                throw new ArgumentNullException(nameof(metric));

            try
            {
                // Enrich metric with system context
                metric.Context["MachineName"] = Environment.MachineName;
                metric.Context["Timestamp"] = metric.Timestamp;

                _policyMetrics.Enqueue(metric);

                _logger.LogTrace("Recorded policy enforcement metric: {PolicyType} for {Recipient} -> {Outcome}",
                    metric.PolicyType, metric.Recipient, metric.Outcome);

                // Maintain queue size limits
                await EnforceQueueLimitsAsync();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to record policy enforcement metric");
            }
        }

        /// <summary>
        /// Gets aggregated metrics for a specific time period.
        /// </summary>
        /// <param name="startTime">The start time</param>
        /// <param name="endTime">The end time</param>
        /// <param name="metricTypes">Optional filter for metric types</param>
        /// <returns>The aggregated metrics</returns>
        public async Task<IEnumerable<AggregatedMetric>> GetAggregatedMetricsAsync(
            DateTime startTime, 
            DateTime endTime, 
            IEnumerable<string>? metricTypes = null)
        {
            try
            {
                var aggregatedMetrics = new List<AggregatedMetric>();
                var typeFilter = metricTypes?.ToHashSet() ?? new HashSet<string>();

                // Aggregate cryptographic operation metrics
                if (!metricTypes?.Any() == true || typeFilter.Contains("CryptographicOperation"))
                {
                    var cryptoMetrics = await AggregateCryptographicMetricsAsync(startTime, endTime);
                    aggregatedMetrics.AddRange(cryptoMetrics);
                }

                // Aggregate performance metrics
                if (!metricTypes?.Any() == true || typeFilter.Contains("PerformanceMetric"))
                {
                    var perfMetrics = await AggregatePerformanceMetricsAsync(startTime, endTime);
                    aggregatedMetrics.AddRange(perfMetrics);
                }

                // Aggregate policy enforcement metrics
                if (!metricTypes?.Any() == true || typeFilter.Contains("PolicyEnforcement"))
                {
                    var policyMetrics = await AggregatePolicyMetricsAsync(startTime, endTime);
                    aggregatedMetrics.AddRange(policyMetrics);
                }

                _logger.LogDebug("Retrieved {Count} aggregated metrics for period {StartTime} to {EndTime}",
                    aggregatedMetrics.Count, startTime, endTime);

                return aggregatedMetrics;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve aggregated metrics");
                throw;
            }
        }

        /// <summary>
        /// Gets real-time metrics for dashboard display.
        /// </summary>
        /// <returns>The current metrics snapshot</returns>
        public async Task<MetricsSnapshot> GetCurrentMetricsAsync()
        {
            try
            {
                var snapshot = new MetricsSnapshot();

                // Collect system metrics
                await CollectSystemMetricsAsync(snapshot);

                // Collect recent operation metrics
                await CollectRecentOperationMetricsAsync(snapshot);

                // Collect health metrics
                await CollectHealthMetricsAsync(snapshot);

                _logger.LogTrace("Generated metrics snapshot with {MetricCount} current values",
                    snapshot.CurrentValues.Count);

                return snapshot;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate current metrics snapshot");
                throw;
            }
        }

        #region Private Methods

        /// <summary>
        /// Periodic aggregation of metrics.
        /// </summary>
        private void AggregateMetrics(object? state)
        {
            try
            {
                _logger.LogTrace("Starting periodic metrics aggregation");

                // In a real implementation, this would persist aggregated metrics
                // to a time-series database or storage system
                
                var cryptoCount = _cryptographicMetrics.Count;
                var perfCount = _performanceMetrics.Count;
                var policyCount = _policyMetrics.Count;

                if (cryptoCount > 0 || perfCount > 0 || policyCount > 0)
                {
                    _logger.LogDebug("Metrics aggregation: {CryptoCount} crypto, {PerfCount} performance, {PolicyCount} policy",
                        cryptoCount, perfCount, policyCount);
                }

                // TODO: Implement actual aggregation and persistence logic
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error during metrics aggregation");
            }
        }

        /// <summary>
        /// Enforces queue size limits to prevent memory growth.
        /// </summary>
        private async Task EnforceQueueLimitsAsync()
        {
            await Task.Run(() =>
            {
                lock (_metricsLock)
                {
                    // Dequeue old metrics if queues are too large
                    while (_cryptographicMetrics.Count > _configuration.MaxQueueSize)
                    {
                        _cryptographicMetrics.TryDequeue(out _);
                    }

                    while (_performanceMetrics.Count > _configuration.MaxQueueSize)
                    {
                        _performanceMetrics.TryDequeue(out _);
                    }

                    while (_policyMetrics.Count > _configuration.MaxQueueSize)
                    {
                        _policyMetrics.TryDequeue(out _);
                    }
                }
            });
        }

        /// <summary>
        /// Aggregates cryptographic operation metrics.
        /// </summary>
        private async Task<IEnumerable<AggregatedMetric>> AggregateCryptographicMetricsAsync(
            DateTime startTime, 
            DateTime endTime)
        {
            await Task.CompletedTask;

            var metrics = _cryptographicMetrics
                .Where(m => m.Timestamp >= startTime && m.Timestamp <= endTime)
                .ToList();

            var aggregated = new List<AggregatedMetric>();

            // Group by operation type and algorithm
            var groups = metrics.GroupBy(m => $"{m.OperationType}_{m.Algorithm}");

            foreach (var group in groups)
            {
                var executionTimes = group.Select(m => (double)m.ExecutionTimeMs).ToList();
                
                if (executionTimes.Any())
                {
                    aggregated.Add(new AggregatedMetric
                    {
                        MetricName = $"CryptographicOperation_{group.Key}_ExecutionTime",
                        PeriodStart = startTime,
                        PeriodEnd = endTime,
                        MinValue = executionTimes.Min(),
                        MaxValue = executionTimes.Max(),
                        AverageValue = executionTimes.Average(),
                        SumValue = executionTimes.Sum(),
                        Count = executionTimes.Count,
                        Breakdown = new Dictionary<string, object>
                        {
                            ["SuccessCount"] = group.Count(m => m.Success),
                            ["FailureCount"] = group.Count(m => !m.Success),
                            ["SuccessRate"] = group.Count(m => m.Success) / (double)group.Count()
                        }
                    });
                }
            }

            return aggregated;
        }

        /// <summary>
        /// Aggregates performance metrics.
        /// </summary>
        private async Task<IEnumerable<AggregatedMetric>> AggregatePerformanceMetricsAsync(
            DateTime startTime, 
            DateTime endTime)
        {
            await Task.CompletedTask;

            var metrics = _performanceMetrics
                .Where(m => m.Timestamp >= startTime && m.Timestamp <= endTime)
                .ToList();

            var aggregated = new List<AggregatedMetric>();

            // Group by metric name
            var groups = metrics.GroupBy(m => m.MetricName);

            foreach (var group in groups)
            {
                var values = group.Select(m => m.Value).ToList();
                
                if (values.Any())
                {
                    aggregated.Add(new AggregatedMetric
                    {
                        MetricName = group.Key,
                        PeriodStart = startTime,
                        PeriodEnd = endTime,
                        MinValue = values.Min(),
                        MaxValue = values.Max(),
                        AverageValue = values.Average(),
                        SumValue = values.Sum(),
                        Count = values.Count
                    });
                }
            }

            return aggregated;
        }

        /// <summary>
        /// Aggregates policy enforcement metrics.
        /// </summary>
        private async Task<IEnumerable<AggregatedMetric>> AggregatePolicyMetricsAsync(
            DateTime startTime, 
            DateTime endTime)
        {
            await Task.CompletedTask;

            var metrics = _policyMetrics
                .Where(m => m.Timestamp >= startTime && m.Timestamp <= endTime)
                .ToList();

            var aggregated = new List<AggregatedMetric>();

            // Aggregate by policy type
            var groups = metrics.GroupBy(m => m.PolicyType);

            foreach (var group in groups)
            {
                var outcomes = group.ToList();
                
                aggregated.Add(new AggregatedMetric
                {
                    MetricName = $"PolicyEnforcement_{group.Key}_Outcomes",
                    PeriodStart = startTime,
                    PeriodEnd = endTime,
                    Count = outcomes.Count,
                    Breakdown = new Dictionary<string, object>
                    {
                        ["SuccessCount"] = outcomes.Count(m => m.Outcome == PolicyOutcome.Success),
                        ["FailureCount"] = outcomes.Count(m => m.Outcome == PolicyOutcome.Failure),
                        ["ViolationCount"] = outcomes.Count(m => m.Outcome == PolicyOutcome.Violation),
                        ["FallbackCount"] = outcomes.Count(m => m.Outcome == PolicyOutcome.Fallback)
                    }
                });
            }

            return aggregated;
        }

        /// <summary>
        /// Collects system performance metrics.
        /// </summary>
        private async Task CollectSystemMetricsAsync(MetricsSnapshot snapshot)
        {
            try
            {
                // CPU usage
                var cpuUsage = _cpuCounter.NextValue();
                snapshot.CurrentValues["CpuUsage"] = cpuUsage;

                // Memory usage
                var availableMemoryMB = _memoryCounter.NextValue();
                var totalMemoryMB = GC.GetTotalMemory(false) / 1024 / 1024;
                snapshot.CurrentValues["MemoryUsage"] = totalMemoryMB;
                snapshot.CurrentValues["AvailableMemory"] = availableMemoryMB;

                // Process-specific metrics
                snapshot.CurrentValues["ProcessMemoryMB"] = _currentProcess.WorkingSet64 / 1024 / 1024;
                snapshot.CurrentValues["ProcessCpuTime"] = _currentProcess.TotalProcessorTime.TotalMilliseconds;
                snapshot.CurrentValues["ThreadCount"] = _currentProcess.Threads.Count;

                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect system metrics");
            }
        }

        /// <summary>
        /// Collects recent operation metrics.
        /// </summary>
        private async Task CollectRecentOperationMetricsAsync(MetricsSnapshot snapshot)
        {
            try
            {
                var recentWindow = DateTime.UtcNow.AddMinutes(-5); // Last 5 minutes

                // Recent cryptographic operations
                var recentCrypto = _cryptographicMetrics
                    .Where(m => m.Timestamp >= recentWindow)
                    .ToList();

                if (recentCrypto.Any())
                {
                    snapshot.CurrentValues["RecentCryptographicOperations"] = recentCrypto.Count;
                    snapshot.CurrentValues["RecentCryptographicSuccessRate"] = 
                        recentCrypto.Count(m => m.Success) / (double)recentCrypto.Count * 100;
                    snapshot.CurrentValues["AverageCryptographicTime"] = 
                        recentCrypto.Average(m => m.ExecutionTimeMs);
                }

                // Recent policy decisions
                var recentPolicy = _policyMetrics
                    .Where(m => m.Timestamp >= recentWindow)
                    .ToList();

                if (recentPolicy.Any())
                {
                    snapshot.CurrentValues["RecentPolicyDecisions"] = recentPolicy.Count;
                    snapshot.CurrentValues["RecentPolicyViolations"] = 
                        recentPolicy.Count(m => m.Outcome == PolicyOutcome.Violation);
                }

                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect recent operation metrics");
            }
        }

        /// <summary>
        /// Collects health-related metrics.
        /// </summary>
        private async Task CollectHealthMetricsAsync(MetricsSnapshot snapshot)
        {
            try
            {
                // Queue sizes
                snapshot.CurrentValues["CryptographicMetricsQueueSize"] = _cryptographicMetrics.Count;
                snapshot.CurrentValues["PerformanceMetricsQueueSize"] = _performanceMetrics.Count;
                snapshot.CurrentValues["PolicyMetricsQueueSize"] = _policyMetrics.Count;

                // System health indicators
                snapshot.CurrentValues["UptimeSeconds"] = Environment.TickCount64 / 1000.0;
                snapshot.CurrentValues["GCTotalMemory"] = GC.GetTotalMemory(false);
                snapshot.CurrentValues["GCCollectionCount"] = 
                    GC.CollectionCount(0) + GC.CollectionCount(1) + GC.CollectionCount(2);

                await Task.CompletedTask;
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to collect health metrics");
            }
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Disposes of resources used by this service.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of resources used by this service.
        /// </summary>
        /// <param name="disposing">True if disposing managed resources</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                _aggregationTimer?.Dispose();
                _cpuCounter?.Dispose();
                _memoryCounter?.Dispose();
                _currentProcess?.Dispose();
                
                _disposed = true;
            }
        }

        #endregion
    }

    /// <summary>
    /// Configuration settings for metrics collection.
    /// </summary>
    public class MetricsConfiguration
    {
        /// <summary>
        /// Gets or sets the aggregation interval in seconds.
        /// </summary>
        public int AggregationIntervalSeconds { get; set; } = 60;

        /// <summary>
        /// Gets or sets the maximum queue size for in-memory metrics.
        /// </summary>
        public int MaxQueueSize { get; set; } = 10000;

        /// <summary>
        /// Gets or sets whether to collect detailed system metrics.
        /// </summary>
        public bool CollectSystemMetrics { get; set; } = true;

        /// <summary>
        /// Gets or sets the retention period for raw metrics in hours.
        /// </summary>
        public int RawMetricsRetentionHours { get; set; } = 24;

        /// <summary>
        /// Gets or sets the retention period for aggregated metrics in days.
        /// </summary>
        public int AggregatedMetricsRetentionDays { get; set; } = 90;

        /// <summary>
        /// Gets or sets custom metric collection intervals.
        /// </summary>
        public Dictionary<string, int> CustomIntervals { get; set; } = new()
        {
            ["SystemMetrics"] = 30,
            ["CryptographicMetrics"] = 1,
            ["PolicyMetrics"] = 5
        };
    }
}