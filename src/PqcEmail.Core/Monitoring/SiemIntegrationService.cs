using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Monitoring
{
    /// <summary>
    /// Provides integration with Security Information and Event Management (SIEM) systems
    /// for centralized audit logging and security monitoring.
    /// </summary>
    public class SiemIntegrationService : ISiemIntegrationService, IDisposable
    {
        private readonly ILogger<SiemIntegrationService> _logger;
        private readonly HttpClient _httpClient;
        private readonly SiemConfiguration _configuration;
        private bool _disposed;

        /// <summary>
        /// Initializes a new instance of the <see cref="SiemIntegrationService"/> class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="httpClient">HTTP client for SIEM communication</param>
        /// <param name="configuration">SIEM configuration settings</param>
        public SiemIntegrationService(
            ILogger<SiemIntegrationService> logger,
            HttpClient httpClient,
            SiemConfiguration configuration)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

            ConfigureHttpClient();
        }

        /// <summary>
        /// Sends an audit event to the configured SIEM system.
        /// </summary>
        /// <param name="auditEvent">The audit event to send</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task SendAuditEventAsync(PolicyAuditEvent auditEvent)
        {
            if (auditEvent == null)
                throw new ArgumentNullException(nameof(auditEvent));

            if (!_configuration.Enabled)
            {
                _logger.LogTrace("SIEM integration is disabled");
                return;
            }

            try
            {
                var siemEvent = ConvertToSiemEvent(auditEvent);
                var jsonContent = JsonSerializer.Serialize(siemEvent, GetJsonSerializerOptions());
                
                using var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
                
                var response = await _httpClient.PostAsync(_configuration.Endpoint, content);
                
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogTrace("Successfully sent audit event {EventId} to SIEM", auditEvent.EventId);
                }
                else
                {
                    _logger.LogWarning("Failed to send audit event {EventId} to SIEM. Status: {StatusCode}, Reason: {ReasonPhrase}",
                        auditEvent.EventId, response.StatusCode, response.ReasonPhrase);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending audit event {EventId} to SIEM", auditEvent.EventId);
            }
        }

        /// <summary>
        /// Sends a batch of audit events to the configured SIEM system.
        /// </summary>
        /// <param name="auditEvents">The audit events to send</param>
        /// <returns>A task representing the asynchronous operation</returns>
        public async Task SendAuditEventsBatchAsync(IEnumerable<PolicyAuditEvent> auditEvents)
        {
            if (auditEvents == null)
                throw new ArgumentNullException(nameof(auditEvents));

            if (!_configuration.Enabled)
            {
                _logger.LogTrace("SIEM integration is disabled");
                return;
            }

            try
            {
                var siemEvents = new List<SiemAuditEvent>();
                foreach (var auditEvent in auditEvents)
                {
                    siemEvents.Add(ConvertToSiemEvent(auditEvent));
                }

                if (siemEvents.Count == 0)
                {
                    _logger.LogTrace("No audit events to send to SIEM");
                    return;
                }

                var batchPayload = new
                {
                    events = siemEvents,
                    batch_id = Guid.NewGuid(),
                    timestamp = DateTime.UtcNow,
                    source = "PQC-Email-System"
                };

                var jsonContent = JsonSerializer.Serialize(batchPayload, GetJsonSerializerOptions());
                using var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
                
                var batchEndpoint = _configuration.BatchEndpoint ?? _configuration.Endpoint;
                var response = await _httpClient.PostAsync(batchEndpoint, content);
                
                if (response.IsSuccessStatusCode)
                {
                    _logger.LogInformation("Successfully sent {Count} audit events to SIEM", siemEvents.Count);
                }
                else
                {
                    _logger.LogWarning("Failed to send {Count} audit events to SIEM. Status: {StatusCode}, Reason: {ReasonPhrase}",
                        siemEvents.Count, response.StatusCode, response.ReasonPhrase);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Error sending batch audit events to SIEM");
            }
        }

        /// <summary>
        /// Tests the connection to the SIEM system.
        /// </summary>
        /// <returns>True if the connection is successful</returns>
        public async Task<bool> TestConnectionAsync()
        {
            if (!_configuration.Enabled)
                return false;

            try
            {
                var testEvent = new SiemAuditEvent
                {
                    EventId = Guid.NewGuid().ToString(),
                    Timestamp = DateTime.UtcNow,
                    EventType = "SystemTest",
                    Source = "PQC-Email-System",
                    Severity = "Info",
                    Category = "System",
                    Message = "SIEM connection test",
                    Data = new Dictionary<string, object>
                    {
                        ["test"] = true,
                        ["version"] = "1.0"
                    }
                };

                var jsonContent = JsonSerializer.Serialize(testEvent, GetJsonSerializerOptions());
                using var content = new StringContent(jsonContent, Encoding.UTF8, "application/json");
                
                var testEndpoint = _configuration.HealthCheckEndpoint ?? _configuration.Endpoint;
                var response = await _httpClient.PostAsync(testEndpoint, content);
                
                var isSuccessful = response.IsSuccessStatusCode;
                _logger.LogInformation("SIEM connection test {Status}", isSuccessful ? "successful" : "failed");
                
                return isSuccessful;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SIEM connection test failed");
                return false;
            }
        }

        #region Private Methods

        /// <summary>
        /// Converts a PolicyAuditEvent to a SIEM-compatible event format.
        /// </summary>
        /// <param name="auditEvent">The audit event to convert</param>
        /// <returns>The SIEM-compatible event</returns>
        private SiemAuditEvent ConvertToSiemEvent(PolicyAuditEvent auditEvent)
        {
            var severity = DetermineSeverity(auditEvent.Outcome);
            var category = DetermineCategory(auditEvent.EventType);
            
            return new SiemAuditEvent
            {
                EventId = auditEvent.EventId.ToString(),
                Timestamp = auditEvent.Timestamp,
                EventType = auditEvent.EventType,
                Source = "PQC-Email-System",
                Severity = severity,
                Category = category,
                Actor = auditEvent.Actor,
                RecipientEmail = auditEvent.RecipientEmail,
                SenderEmail = auditEvent.SenderEmail,
                Message = FormatEventMessage(auditEvent),
                PolicyDecision = auditEvent.PolicyDecision,
                Outcome = auditEvent.Outcome.ToString(),
                AlgorithmsUsed = auditEvent.AlgorithmsUsed,
                Data = auditEvent.EventData,
                Compliance = new Dictionary<string, object>
                {
                    ["sox_relevant"] = IsSoxRelevant(auditEvent),
                    ["gdpr_relevant"] = IsGdprRelevant(auditEvent),
                    ["ffiec_relevant"] = IsFfiecRelevant(auditEvent)
                }
            };
        }

        /// <summary>
        /// Determines the SIEM severity level based on the policy outcome.
        /// </summary>
        /// <param name="outcome">The policy outcome</param>
        /// <returns>The SIEM severity level</returns>
        private static string DetermineSeverity(PolicyOutcome outcome)
        {
            return outcome switch
            {
                PolicyOutcome.Success => "Info",
                PolicyOutcome.Fallback => "Warning",
                PolicyOutcome.Violation => "High",
                PolicyOutcome.Failure => "Critical",
                _ => "Info"
            };
        }

        /// <summary>
        /// Determines the SIEM category based on the event type.
        /// </summary>
        /// <param name="eventType">The event type</param>
        /// <returns>The SIEM category</returns>
        private static string DetermineCategory(string eventType)
        {
            return eventType switch
            {
                "PolicyDecision" => "AccessControl",
                "PolicyViolation" => "Security",
                "AlgorithmFallback" => "Cryptography",
                "KeyGeneration" => "Cryptography",
                "KeyRotation" => "Cryptography",
                "CertificateValidation" => "PKI",
                _ => "General"
            };
        }

        /// <summary>
        /// Formats an event message for SIEM consumption.
        /// </summary>
        /// <param name="auditEvent">The audit event</param>
        /// <returns>The formatted message</returns>
        private static string FormatEventMessage(PolicyAuditEvent auditEvent)
        {
            var message = $"PQC Email {auditEvent.EventType}";
            
            if (!string.IsNullOrEmpty(auditEvent.RecipientEmail))
                message += $" for {auditEvent.RecipientEmail}";
            
            if (!string.IsNullOrEmpty(auditEvent.PolicyDecision))
                message += $": {auditEvent.PolicyDecision}";
            
            message += $" -> {auditEvent.Outcome}";
            
            return message;
        }

        /// <summary>
        /// Determines if an event is relevant for SOX compliance.
        /// </summary>
        /// <param name="auditEvent">The audit event</param>
        /// <returns>True if SOX relevant</returns>
        private static bool IsSoxRelevant(PolicyAuditEvent auditEvent)
        {
            // SOX requires comprehensive audit trails for financial data
            return auditEvent.EventType == "PolicyDecision" || 
                   auditEvent.EventType == "PolicyViolation" ||
                   auditEvent.AlgorithmsUsed.Count > 0;
        }

        /// <summary>
        /// Determines if an event is relevant for GDPR compliance.
        /// </summary>
        /// <param name="auditEvent">The audit event</param>
        /// <returns>True if GDPR relevant</returns>
        private static bool IsGdprRelevant(PolicyAuditEvent auditEvent)
        {
            // GDPR requires privacy and data protection audit trails
            return auditEvent.EventType == "PolicyDecision" || 
                   auditEvent.EventType == "PolicyViolation" ||
                   !string.IsNullOrEmpty(auditEvent.RecipientEmail) ||
                   !string.IsNullOrEmpty(auditEvent.SenderEmail);
        }

        /// <summary>
        /// Determines if an event is relevant for FFIEC compliance.
        /// </summary>
        /// <param name="auditEvent">The audit event</param>
        /// <returns>True if FFIEC relevant</returns>
        private static bool IsFfiecRelevant(PolicyAuditEvent auditEvent)
        {
            // FFIEC requires comprehensive security monitoring
            return auditEvent.Outcome == PolicyOutcome.Violation ||
                   auditEvent.Outcome == PolicyOutcome.Failure ||
                   auditEvent.EventType == "AlgorithmFallback";
        }

        /// <summary>
        /// Configures the HTTP client for SIEM communication.
        /// </summary>
        private void ConfigureHttpClient()
        {
            _httpClient.Timeout = TimeSpan.FromSeconds(_configuration.TimeoutSeconds);
            
            // Add authentication headers if configured
            if (!string.IsNullOrEmpty(_configuration.ApiKey))
            {
                _httpClient.DefaultRequestHeaders.Add("X-API-Key", _configuration.ApiKey);
            }
            
            if (!string.IsNullOrEmpty(_configuration.BearerToken))
            {
                _httpClient.DefaultRequestHeaders.Add("Authorization", $"Bearer {_configuration.BearerToken}");
            }

            // Add custom headers
            foreach (var header in _configuration.CustomHeaders)
            {
                _httpClient.DefaultRequestHeaders.Add(header.Key, header.Value);
            }
        }

        /// <summary>
        /// Gets the JSON serializer options for SIEM communication.
        /// </summary>
        /// <returns>The serializer options</returns>
        private static JsonSerializerOptions GetJsonSerializerOptions()
        {
            return new JsonSerializerOptions
            {
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
                WriteIndented = false,
                DefaultIgnoreCondition = System.Text.Json.Serialization.JsonIgnoreCondition.WhenWritingNull
            };
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
                _httpClient?.Dispose();
                _disposed = true;
            }
        }

        #endregion
    }

    /// <summary>
    /// Represents a SIEM-compatible audit event.
    /// </summary>
    public class SiemAuditEvent
    {
        public string EventId { get; set; } = string.Empty;
        public DateTime Timestamp { get; set; }
        public string EventType { get; set; } = string.Empty;
        public string Source { get; set; } = string.Empty;
        public string Severity { get; set; } = string.Empty;
        public string Category { get; set; } = string.Empty;
        public string? Actor { get; set; }
        public string? RecipientEmail { get; set; }
        public string? SenderEmail { get; set; }
        public string Message { get; set; } = string.Empty;
        public string? PolicyDecision { get; set; }
        public string Outcome { get; set; } = string.Empty;
        public Dictionary<string, string> AlgorithmsUsed { get; set; } = new();
        public Dictionary<string, object> Data { get; set; } = new();
        public Dictionary<string, object> Compliance { get; set; } = new();
    }

    /// <summary>
    /// Configuration settings for SIEM integration.
    /// </summary>
    public class SiemConfiguration
    {
        public bool Enabled { get; set; } = false;
        public string Endpoint { get; set; } = string.Empty;
        public string? BatchEndpoint { get; set; }
        public string? HealthCheckEndpoint { get; set; }
        public string? ApiKey { get; set; }
        public string? BearerToken { get; set; }
        public int TimeoutSeconds { get; set; } = 30;
        public Dictionary<string, string> CustomHeaders { get; set; } = new();
    }
}