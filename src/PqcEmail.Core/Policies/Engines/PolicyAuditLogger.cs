using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Policies.Engines
{
    /// <summary>
    /// Implements comprehensive audit logging for PQC email policy decisions and enforcement.
    /// </summary>
    public class PolicyAuditLogger : IPolicyAuditLogger, IDisposable
    {
        private readonly ILogger<PolicyAuditLogger> _logger;
        private readonly AuditPolicy _auditPolicy;
        private readonly string _logFilePath;
        private readonly object _fileLock = new object();
        private bool _disposed;

        // In-memory cache for recent audit events (for querying)
        private readonly List<PolicyAuditEvent> _eventCache = new();
        private readonly object _cacheLock = new object();
        private const int MaxCacheSize = 1000;

        /// <summary>
        /// Initializes a new instance of the <see cref="PolicyAuditLogger"/> class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="auditPolicy">The audit policy configuration</param>
        public PolicyAuditLogger(ILogger<PolicyAuditLogger> logger, AuditPolicy auditPolicy)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _auditPolicy = auditPolicy ?? throw new ArgumentNullException(nameof(auditPolicy));

            // Determine log file path
            _logFilePath = !string.IsNullOrEmpty(_auditPolicy.CustomLogPath) 
                ? _auditPolicy.CustomLogPath 
                : Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), 
                               "PqcEmail", "Logs", "policy-audit.json");

            EnsureLogDirectoryExists();
        }

        /// <summary>
        /// Logs a policy decision event.
        /// </summary>
        /// <param name="auditEvent">The audit event to log</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task LogPolicyDecisionAsync(PolicyAuditEvent auditEvent)
        {
            if (auditEvent == null)
                throw new ArgumentNullException(nameof(auditEvent));

            if (!_auditPolicy.LogPolicyDecisions)
            {
                _logger.LogTrace("Policy decision logging is disabled");
                return;
            }

            // Enhance event with additional metadata
            auditEvent.EventData["MachineName"] = Environment.MachineName;
            auditEvent.EventData["UserName"] = Environment.UserName;
            auditEvent.EventData["ProcessId"] = Environment.ProcessId;

            await LogEventAsync(auditEvent, "PolicyDecision");
        }

        /// <summary>
        /// Logs a policy violation event.
        /// </summary>
        /// <param name="violation">The policy violation to log</param>
        /// <param name="context">Additional context information</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task LogPolicyViolationAsync(PolicyViolation violation, Dictionary<string, object>? context = null)
        {
            if (violation == null)
                throw new ArgumentNullException(nameof(violation));

            if (!_auditPolicy.LogSecurityViolations)
            {
                _logger.LogTrace("Policy violation logging is disabled");
                return;
            }

            var auditEvent = new PolicyAuditEvent
            {
                EventType = "PolicyViolation",
                PolicyDecision = violation.Type.ToString(),
                Outcome = PolicyOutcome.Violation,
                EventData = context ?? new Dictionary<string, object>()
            };

            // Add violation details
            auditEvent.EventData["ViolationType"] = violation.Type;
            auditEvent.EventData["Severity"] = violation.Severity;
            auditEvent.EventData["Message"] = violation.Message;
            auditEvent.EventData["PolicySetting"] = violation.PolicySetting;
            auditEvent.EventData["AttemptedValue"] = violation.AttemptedValue;
            auditEvent.EventData["ExpectedValue"] = violation.ExpectedValue;

            await LogEventAsync(auditEvent, "PolicyViolation");
        }

        /// <summary>
        /// Logs an algorithm fallback event.
        /// </summary>
        /// <param name="fallbackEvent">The fallback event to log</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task LogFallbackEventAsync(AlgorithmFallbackEvent fallbackEvent)
        {
            if (fallbackEvent == null)
                throw new ArgumentNullException(nameof(fallbackEvent));

            if (!_auditPolicy.LogFallbackEvents)
            {
                _logger.LogTrace("Fallback event logging is disabled");
                return;
            }

            var auditEvent = new PolicyAuditEvent
            {
                EventType = "AlgorithmFallback",
                RecipientEmail = fallbackEvent.RecipientEmail,
                PolicyDecision = $"Fallback from {fallbackEvent.OriginalAlgorithm} to {fallbackEvent.FallbackAlgorithm}",
                Outcome = fallbackEvent.Successful ? PolicyOutcome.Fallback : PolicyOutcome.Failure,
                AlgorithmsUsed = new Dictionary<string, string>
                {
                    ["Original"] = fallbackEvent.OriginalAlgorithm,
                    ["Fallback"] = fallbackEvent.FallbackAlgorithm
                },
                EventData = new Dictionary<string, object>
                {
                    ["Reason"] = fallbackEvent.Reason,
                    ["AttemptNumber"] = fallbackEvent.AttemptNumber,
                    ["Successful"] = fallbackEvent.Successful
                }
            };

            await LogEventAsync(auditEvent, "AlgorithmFallback");
        }

        /// <summary>
        /// Gets audit events for a specific time period.
        /// </summary>
        /// <param name="startTime">The start time for the query</param>
        /// <param name="endTime">The end time for the query</param>
        /// <param name="eventTypes">Optional filter for event types</param>
        /// <returns>The list of audit events</returns>
        public async Task<IEnumerable<PolicyAuditEvent>> GetAuditEventsAsync(
            DateTime startTime, 
            DateTime endTime, 
            IEnumerable<string>? eventTypes = null)
        {
            var events = new List<PolicyAuditEvent>();

            // First, check in-memory cache
            lock (_cacheLock)
            {
                var cachedEvents = _eventCache
                    .Where(e => e.Timestamp >= startTime && e.Timestamp <= endTime)
                    .Where(e => eventTypes == null || eventTypes.Contains(e.EventType));
                
                events.AddRange(cachedEvents);
            }

            // If we need more events or don't have cache coverage, read from file
            if (File.Exists(_logFilePath))
            {
                try
                {
                    var fileEvents = await ReadEventsFromFileAsync(startTime, endTime, eventTypes);
                    
                    // Merge and deduplicate events
                    var allEvents = events.Concat(fileEvents)
                        .GroupBy(e => e.EventId)
                        .Select(g => g.First())
                        .OrderBy(e => e.Timestamp);

                    events = allEvents.ToList();
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, "Failed to read audit events from log file");
                }
            }

            _logger.LogDebug("Retrieved {EventCount} audit events between {StartTime} and {EndTime}", 
                events.Count, startTime, endTime);

            return events;
        }

        #region Private Methods

        /// <summary>
        /// Logs an audit event to all configured destinations.
        /// </summary>
        /// <param name="auditEvent">The audit event to log</param>
        /// <param name="category">The log category</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task LogEventAsync(PolicyAuditEvent auditEvent, string category)
        {
            try
            {
                // Log to structured logger based on severity
                var logLevel = DetermineLogLevel(auditEvent);
                if (ShouldLog(logLevel))
                {
                    _logger.Log(logLevel, 
                        "PQC Email Policy {EventType}: {PolicyDecision} for {RecipientEmail} -> {Outcome}",
                        auditEvent.EventType,
                        auditEvent.PolicyDecision,
                        auditEvent.RecipientEmail,
                        auditEvent.Outcome);
                }

                // Log to Windows Event Log if detailed logging is enabled
                if (_auditPolicy.EnableDetailedLogging)
                {
                    await LogToWindowsEventLogAsync(auditEvent, category);
                }

                // Log to custom file if configured
                if (!string.IsNullOrEmpty(_logFilePath))
                {
                    await LogToFileAsync(auditEvent);
                }

                // Add to in-memory cache
                AddToCache(auditEvent);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to log audit event {EventId}", auditEvent.EventId);
            }
        }

        /// <summary>
        /// Logs an audit event to the Windows Event Log.
        /// </summary>
        /// <param name="auditEvent">The audit event to log</param>
        /// <param name="category">The log category</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task LogToWindowsEventLogAsync(PolicyAuditEvent auditEvent, string category)
        {
            try
            {
                const string sourceName = "PQC Email";
                
                if (!EventLog.SourceExists(sourceName))
                {
                    EventLog.CreateEventSource(sourceName, "Application");
                }

                var eventType = auditEvent.Outcome switch
                {
                    PolicyOutcome.Success => EventLogEntryType.Information,
                    PolicyOutcome.Fallback => EventLogEntryType.Warning,
                    PolicyOutcome.Violation => EventLogEntryType.Warning,
                    PolicyOutcome.Failure => EventLogEntryType.Error,
                    _ => EventLogEntryType.Information
                };

                var message = $"PQC Email Policy {category}\n" +
                             $"Event ID: {auditEvent.EventId}\n" +
                             $"Timestamp: {auditEvent.Timestamp:yyyy-MM-dd HH:mm:ss}\n" +
                             $"Event Type: {auditEvent.EventType}\n" +
                             $"Recipient: {auditEvent.RecipientEmail}\n" +
                             $"Sender: {auditEvent.SenderEmail}\n" +
                             $"Decision: {auditEvent.PolicyDecision}\n" +
                             $"Outcome: {auditEvent.Outcome}\n" +
                             $"Algorithms: {string.Join(", ", auditEvent.AlgorithmsUsed.Select(kvp => $"{kvp.Key}={kvp.Value}"))}\n" +
                             $"Additional Data: {JsonSerializer.Serialize(auditEvent.EventData)}";

                EventLog.WriteEntry(sourceName, message, eventType);
                
                _logger.LogTrace("Logged audit event {EventId} to Windows Event Log", auditEvent.EventId);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to write audit event to Windows Event Log");
            }

            await Task.CompletedTask;
        }

        /// <summary>
        /// Logs an audit event to the custom log file.
        /// </summary>
        /// <param name="auditEvent">The audit event to log</param>
        /// <returns>A task representing the asynchronous operation</returns>
        private async Task LogToFileAsync(PolicyAuditEvent auditEvent)
        {
            try
            {
                var logEntry = new
                {
                    auditEvent.EventId,
                    auditEvent.Timestamp,
                    auditEvent.EventType,
                    auditEvent.Actor,
                    auditEvent.RecipientEmail,
                    auditEvent.SenderEmail,
                    auditEvent.PolicyDecision,
                    auditEvent.AlgorithmsUsed,
                    auditEvent.Outcome,
                    auditEvent.EventData,
                    MachineName = Environment.MachineName,
                    ProcessId = Environment.ProcessId
                };

                var json = JsonSerializer.Serialize(logEntry, new JsonSerializerOptions 
                { 
                    WriteIndented = false,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });

                lock (_fileLock)
                {
                    File.AppendAllText(_logFilePath, json + Environment.NewLine);
                }

                _logger.LogTrace("Logged audit event {EventId} to file {LogFile}", auditEvent.EventId, _logFilePath);
            }
            catch (Exception ex)
            {
                _logger.LogWarning(ex, "Failed to write audit event to log file");
            }

            await Task.CompletedTask;
        }

        /// <summary>
        /// Adds an audit event to the in-memory cache.
        /// </summary>
        /// <param name="auditEvent">The audit event to cache</param>
        private void AddToCache(PolicyAuditEvent auditEvent)
        {
            lock (_cacheLock)
            {
                _eventCache.Add(auditEvent);

                // Maintain cache size limit
                if (_eventCache.Count > MaxCacheSize)
                {
                    // Remove oldest events
                    var toRemove = _eventCache.Count - MaxCacheSize;
                    _eventCache.RemoveRange(0, toRemove);
                }
            }
        }

        /// <summary>
        /// Reads audit events from the log file for a specific time period.
        /// </summary>
        /// <param name="startTime">The start time</param>
        /// <param name="endTime">The end time</param>
        /// <param name="eventTypes">Optional event type filter</param>
        /// <returns>The list of audit events</returns>
        private async Task<List<PolicyAuditEvent>> ReadEventsFromFileAsync(
            DateTime startTime, 
            DateTime endTime, 
            IEnumerable<string>? eventTypes)
        {
            var events = new List<PolicyAuditEvent>();
            var eventTypeSet = eventTypes?.ToHashSet();

            try
            {
                var lines = await File.ReadAllLinesAsync(_logFilePath);

                foreach (var line in lines)
                {
                    if (string.IsNullOrWhiteSpace(line))
                        continue;

                    try
                    {
                        var logEntry = JsonSerializer.Deserialize<JsonElement>(line);
                        
                        if (logEntry.TryGetProperty("timestamp", out var timestampProp) &&
                            DateTime.TryParse(timestampProp.GetString(), out var timestamp))
                        {
                            if (timestamp >= startTime && timestamp <= endTime)
                            {
                                var eventType = logEntry.GetProperty("eventType").GetString();
                                if (eventTypeSet == null || eventTypeSet.Contains(eventType))
                                {
                                    var auditEvent = ParseLogEntryToAuditEvent(logEntry);
                                    if (auditEvent != null)
                                    {
                                        events.Add(auditEvent);
                                    }
                                }
                            }
                        }
                    }
                    catch (JsonException ex)
                    {
                        _logger.LogWarning(ex, "Failed to parse log entry: {LogEntry}", line);
                    }
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to read events from log file");
            }

            return events;
        }

        /// <summary>
        /// Parses a JSON log entry into a PolicyAuditEvent.
        /// </summary>
        /// <param name="logEntry">The JSON log entry</param>
        /// <returns>The parsed audit event or null if parsing fails</returns>
        private static PolicyAuditEvent? ParseLogEntryToAuditEvent(JsonElement logEntry)
        {
            try
            {
                var auditEvent = new PolicyAuditEvent
                {
                    EventId = Guid.Parse(logEntry.GetProperty("eventId").GetString()!),
                    Timestamp = DateTime.Parse(logEntry.GetProperty("timestamp").GetString()!),
                    EventType = logEntry.GetProperty("eventType").GetString()!,
                    Actor = logEntry.TryGetProperty("actor", out var actorProp) ? actorProp.GetString() : null,
                    RecipientEmail = logEntry.TryGetProperty("recipientEmail", out var recipientProp) ? recipientProp.GetString() : null,
                    SenderEmail = logEntry.TryGetProperty("senderEmail", out var senderProp) ? senderProp.GetString() : null,
                    PolicyDecision = logEntry.TryGetProperty("policyDecision", out var decisionProp) ? decisionProp.GetString() : null
                };

                if (logEntry.TryGetProperty("outcome", out var outcomeProp) &&
                    Enum.TryParse<PolicyOutcome>(outcomeProp.GetString(), out var outcome))
                {
                    auditEvent.Outcome = outcome;
                }

                // Parse algorithms used
                if (logEntry.TryGetProperty("algorithmsUsed", out var algosProp))
                {
                    foreach (var property in algosProp.EnumerateObject())
                    {
                        auditEvent.AlgorithmsUsed[property.Name] = property.Value.GetString() ?? string.Empty;
                    }
                }

                // Parse event data
                if (logEntry.TryGetProperty("eventData", out var dataProp))
                {
                    foreach (var property in dataProp.EnumerateObject())
                    {
                        auditEvent.EventData[property.Name] = property.Value.ValueKind switch
                        {
                            JsonValueKind.String => property.Value.GetString(),
                            JsonValueKind.Number => property.Value.GetDecimal(),
                            JsonValueKind.True => true,
                            JsonValueKind.False => false,
                            _ => property.Value.ToString()
                        };
                    }
                }

                return auditEvent;
            }
            catch (Exception)
            {
                return null;
            }
        }

        /// <summary>
        /// Determines the appropriate log level for an audit event.
        /// </summary>
        /// <param name="auditEvent">The audit event</param>
        /// <returns>The log level</returns>
        private static Microsoft.Extensions.Logging.LogLevel DetermineLogLevel(PolicyAuditEvent auditEvent)
        {
            return auditEvent.Outcome switch
            {
                PolicyOutcome.Success => Microsoft.Extensions.Logging.LogLevel.Information,
                PolicyOutcome.Fallback => Microsoft.Extensions.Logging.LogLevel.Warning,
                PolicyOutcome.Violation => Microsoft.Extensions.Logging.LogLevel.Warning,
                PolicyOutcome.Failure => Microsoft.Extensions.Logging.LogLevel.Error,
                _ => Microsoft.Extensions.Logging.LogLevel.Information
            };
        }

        /// <summary>
        /// Determines if an event should be logged based on the audit policy log level.
        /// </summary>
        /// <param name="logLevel">The log level</param>
        /// <returns>True if the event should be logged</returns>
        private bool ShouldLog(Microsoft.Extensions.Logging.LogLevel logLevel)
        {
            return logLevel switch
            {
                Microsoft.Extensions.Logging.LogLevel.Error => _auditPolicy.LogLevel >= LogLevel.Error,
                Microsoft.Extensions.Logging.LogLevel.Warning => _auditPolicy.LogLevel >= LogLevel.Warning,
                Microsoft.Extensions.Logging.LogLevel.Information => _auditPolicy.LogLevel >= LogLevel.Information,
                Microsoft.Extensions.Logging.LogLevel.Debug => _auditPolicy.LogLevel >= LogLevel.Debug,
                _ => true
            };
        }

        /// <summary>
        /// Ensures the log directory exists.
        /// </summary>
        private void EnsureLogDirectoryExists()
        {
            try
            {
                var directory = Path.GetDirectoryName(_logFilePath);
                if (!string.IsNullOrEmpty(directory) && !Directory.Exists(directory))
                {
                    Directory.CreateDirectory(directory);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to create log directory for path: {LogPath}", _logFilePath);
            }
        }

        #endregion

        #region IDisposable Implementation

        /// <summary>
        /// Disposes of resources used by this audit logger.
        /// </summary>
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }

        /// <summary>
        /// Disposes of resources used by this audit logger.
        /// </summary>
        /// <param name="disposing">True if disposing managed resources</param>
        protected virtual void Dispose(bool disposing)
        {
            if (!_disposed && disposing)
            {
                // Clear cache
                lock (_cacheLock)
                {
                    _eventCache.Clear();
                }
                
                _disposed = true;
            }
        }

        #endregion
    }
}