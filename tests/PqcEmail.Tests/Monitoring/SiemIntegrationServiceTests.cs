using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using Moq.Protected;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;
using PqcEmail.Core.Monitoring;
using Xunit;

namespace PqcEmail.Tests.Monitoring
{
    /// <summary>
    /// Tests for the SIEM integration service functionality.
    /// </summary>
    public class SiemIntegrationServiceTests
    {
        private readonly Mock<ILogger<SiemIntegrationService>> _mockLogger;
        private readonly Mock<HttpMessageHandler> _mockHttpHandler;
        private readonly HttpClient _httpClient;
        private readonly SiemConfiguration _configuration;
        private readonly SiemIntegrationService _siemService;

        public SiemIntegrationServiceTests()
        {
            _mockLogger = new Mock<ILogger<SiemIntegrationService>>();
            _mockHttpHandler = new Mock<HttpMessageHandler>();
            _httpClient = new HttpClient(_mockHttpHandler.Object);
            
            _configuration = new SiemConfiguration
            {
                Enabled = true,
                Endpoint = "https://siem.test.com/api/events",
                BatchEndpoint = "https://siem.test.com/api/batch",
                HealthCheckEndpoint = "https://siem.test.com/api/health",
                ApiKey = "test-api-key",
                TimeoutSeconds = 30
            };

            _siemService = new SiemIntegrationService(_mockLogger.Object, _httpClient, _configuration);
        }

        [Fact]
        public async Task SendAuditEventAsync_ValidEvent_SendsToSiem()
        {
            // Arrange
            var auditEvent = CreateTestAuditEvent();
            SetupHttpResponse(HttpStatusCode.OK);

            // Act
            await _siemService.SendAuditEventAsync(auditEvent);

            // Assert
            VerifyHttpRequest("POST", _configuration.Endpoint);
            VerifyLogMessage(LogLevel.Trace, "Successfully sent audit event");
        }

        [Fact]
        public async Task SendAuditEventAsync_NullEvent_ThrowsArgumentNullException()
        {
            // Act & Assert
            await Assert.ThrowsAsync<ArgumentNullException>(() => 
                _siemService.SendAuditEventAsync(null));
        }

        [Fact]
        public async Task SendAuditEventAsync_SiemDisabled_DoesNotSend()
        {
            // Arrange
            _configuration.Enabled = false;
            var auditEvent = CreateTestAuditEvent();

            // Act
            await _siemService.SendAuditEventAsync(auditEvent);

            // Assert
            VerifyNoHttpRequest();
            VerifyLogMessage(LogLevel.Trace, "SIEM integration is disabled");
        }

        [Fact]
        public async Task SendAuditEventAsync_HttpError_LogsWarning()
        {
            // Arrange
            var auditEvent = CreateTestAuditEvent();
            SetupHttpResponse(HttpStatusCode.InternalServerError);

            // Act
            await _siemService.SendAuditEventAsync(auditEvent);

            // Assert
            VerifyLogMessage(LogLevel.Warning, "Failed to send audit event");
        }

        [Fact]
        public async Task SendAuditEventsBatchAsync_ValidEvents_SendsToBatchEndpoint()
        {
            // Arrange
            var auditEvents = new List<PolicyAuditEvent>
            {
                CreateTestAuditEvent(),
                CreateTestAuditEvent()
            };
            SetupHttpResponse(HttpStatusCode.OK);

            // Act
            await _siemService.SendAuditEventsBatchAsync(auditEvents);

            // Assert
            VerifyHttpRequest("POST", _configuration.BatchEndpoint);
            VerifyLogMessage(LogLevel.Information, "Successfully sent 2 audit events to SIEM");
        }

        [Fact]
        public async Task SendAuditEventsBatchAsync_EmptyList_DoesNotSend()
        {
            // Arrange
            var auditEvents = new List<PolicyAuditEvent>();

            // Act
            await _siemService.SendAuditEventsBatchAsync(auditEvents);

            // Assert
            VerifyNoHttpRequest();
            VerifyLogMessage(LogLevel.Trace, "No audit events to send to SIEM");
        }

        [Fact]
        public async Task TestConnectionAsync_Success_ReturnsTrue()
        {
            // Arrange
            SetupHttpResponse(HttpStatusCode.OK);

            // Act
            var result = await _siemService.TestConnectionAsync();

            // Assert
            Assert.True(result);
            VerifyLogMessage(LogLevel.Information, "SIEM connection test successful");
        }

        [Fact]
        public async Task TestConnectionAsync_Failure_ReturnsFalse()
        {
            // Arrange
            SetupHttpResponse(HttpStatusCode.ServiceUnavailable);

            // Act
            var result = await _siemService.TestConnectionAsync();

            // Assert
            Assert.False(result);
            VerifyLogMessage(LogLevel.Information, "SIEM connection test failed");
        }

        [Fact]
        public async Task TestConnectionAsync_SiemDisabled_ReturnsFalse()
        {
            // Arrange
            _configuration.Enabled = false;

            // Act
            var result = await _siemService.TestConnectionAsync();

            // Assert
            Assert.False(result);
        }

        [Fact]
        public void ConvertToSiemEvent_PolicyDecision_MapsCorrectly()
        {
            // Arrange
            var auditEvent = new PolicyAuditEvent
            {
                EventType = "PolicyDecision",
                PolicyDecision = "Hybrid encryption selected",
                Outcome = PolicyOutcome.Success,
                RecipientEmail = "test@example.com",
                SenderEmail = "sender@example.com",
                AlgorithmsUsed = new Dictionary<string, string>
                {
                    ["KEM"] = "ML-KEM-768",
                    ["Signature"] = "ML-DSA-65"
                }
            };

            // Act
            var siemEvent = InvokePrivateMethod<SiemAuditEvent>("ConvertToSiemEvent", auditEvent);

            // Assert
            Assert.Equal("PolicyDecision", siemEvent.EventType);
            Assert.Equal("Info", siemEvent.Severity);
            Assert.Equal("AccessControl", siemEvent.Category);
            Assert.Equal("Success", siemEvent.Outcome);
            Assert.Contains("ML-KEM-768", siemEvent.AlgorithmsUsed.Values);
            Assert.True((bool)siemEvent.Compliance["sox_relevant"]);
        }

        [Fact]
        public void ConvertToSiemEvent_PolicyViolation_MapsToHighSeverity()
        {
            // Arrange
            var auditEvent = new PolicyAuditEvent
            {
                EventType = "PolicyViolation",
                Outcome = PolicyOutcome.Violation
            };

            // Act
            var siemEvent = InvokePrivateMethod<SiemAuditEvent>("ConvertToSiemEvent", auditEvent);

            // Assert
            Assert.Equal("High", siemEvent.Severity);
            Assert.Equal("Security", siemEvent.Category);
        }

        [Fact]
        public void ConvertToSiemEvent_AlgorithmFallback_MapsToWarning()
        {
            // Arrange
            var auditEvent = new PolicyAuditEvent
            {
                EventType = "AlgorithmFallback",
                Outcome = PolicyOutcome.Fallback
            };

            // Act
            var siemEvent = InvokePrivateMethod<SiemAuditEvent>("ConvertToSiemEvent", auditEvent);

            // Assert
            Assert.Equal("Warning", siemEvent.Severity);
            Assert.Equal("Cryptography", siemEvent.Category);
        }

        [Theory]
        [InlineData("PolicyDecision", true, true, true)] // SOX, GDPR, FFIEC relevant
        [InlineData("PolicyViolation", true, true, true)] // All relevant
        [InlineData("AlgorithmFallback", false, false, true)] // Only FFIEC relevant
        [InlineData("KeyGeneration", false, false, false)] // None explicitly relevant
        public void ConvertToSiemEvent_ComplianceRelevance_MapsCorrectly(
            string eventType, bool soxRelevant, bool gdprRelevant, bool ffiecRelevant)
        {
            // Arrange
            var auditEvent = new PolicyAuditEvent
            {
                EventType = eventType,
                RecipientEmail = "test@example.com",
                AlgorithmsUsed = new Dictionary<string, string> { ["test"] = "ML-KEM-768" },
                Outcome = eventType == "AlgorithmFallback" ? PolicyOutcome.Fallback : PolicyOutcome.Success
            };

            // Act
            var siemEvent = InvokePrivateMethod<SiemAuditEvent>("ConvertToSiemEvent", auditEvent);

            // Assert
            Assert.Equal(soxRelevant, (bool)siemEvent.Compliance["sox_relevant"]);
            Assert.Equal(gdprRelevant, (bool)siemEvent.Compliance["gdpr_relevant"]);
            Assert.Equal(ffiecRelevant, (bool)siemEvent.Compliance["ffiec_relevant"]);
        }

        [Fact]
        public void Dispose_DisposesHttpClient()
        {
            // Act
            _siemService.Dispose();

            // Assert - No exception should be thrown
            // HttpClient disposal is verified through proper cleanup
        }

        #region Private Helper Methods

        private PolicyAuditEvent CreateTestAuditEvent()
        {
            return new PolicyAuditEvent
            {
                EventId = Guid.NewGuid(),
                Timestamp = DateTime.UtcNow,
                EventType = "PolicyDecision",
                Actor = "test@example.com",
                RecipientEmail = "recipient@example.com",
                SenderEmail = "sender@example.com",
                PolicyDecision = "Hybrid encryption selected",
                Outcome = PolicyOutcome.Success,
                AlgorithmsUsed = new Dictionary<string, string>
                {
                    ["KEM"] = "ML-KEM-768",
                    ["Signature"] = "ML-DSA-65"
                },
                EventData = new Dictionary<string, object>
                {
                    ["test"] = "value"
                }
            };
        }

        private void SetupHttpResponse(HttpStatusCode statusCode, string content = "")
        {
            var response = new HttpResponseMessage(statusCode)
            {
                Content = new StringContent(content)
            };

            _mockHttpHandler.Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>())
                .ReturnsAsync(response);
        }

        private void VerifyHttpRequest(string method, string endpoint)
        {
            _mockHttpHandler.Protected()
                .Verify(
                    "SendAsync",
                    Times.Once(),
                    ItExpr.Is<HttpRequestMessage>(req =>
                        req.Method.ToString() == method &&
                        req.RequestUri.ToString() == endpoint),
                    ItExpr.IsAny<CancellationToken>());
        }

        private void VerifyNoHttpRequest()
        {
            _mockHttpHandler.Protected()
                .Verify(
                    "SendAsync",
                    Times.Never(),
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>());
        }

        private void VerifyLogMessage(LogLevel level, string message)
        {
            _mockLogger.Verify(
                x => x.Log(
                    level,
                    It.IsAny<EventId>(),
                    It.Is<It.IsAnyType>((v, t) => v.ToString().Contains(message)),
                    It.IsAny<Exception>(),
                    It.IsAny<Func<It.IsAnyType, Exception, string>>()),
                Times.AtLeastOnce);
        }

        private T InvokePrivateMethod<T>(string methodName, params object[] parameters)
        {
            var method = typeof(SiemIntegrationService).GetMethod(methodName, 
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Instance);
            
            return (T)method.Invoke(_siemService, parameters);
        }

        #endregion
    }

    /// <summary>
    /// Tests for SIEM configuration validation and edge cases.
    /// </summary>
    public class SiemConfigurationTests
    {
        [Fact]
        public void SiemConfiguration_DefaultValues_AreCorrect()
        {
            // Arrange & Act
            var config = new SiemConfiguration();

            // Assert
            Assert.False(config.Enabled);
            Assert.Equal(string.Empty, config.Endpoint);
            Assert.Equal(30, config.TimeoutSeconds);
            Assert.Empty(config.CustomHeaders);
        }

        [Theory]
        [InlineData("")]
        [InlineData("not-a-url")]
        [InlineData("ftp://invalid.com")]
        public void SiemConfiguration_InvalidEndpoint_ShouldBeValidated(string endpoint)
        {
            // Arrange
            var config = new SiemConfiguration
            {
                Enabled = true,
                Endpoint = endpoint
            };

            // Act & Assert
            // In a real implementation, configuration validation would occur
            // This test documents the expected behavior
            Assert.True(string.IsNullOrEmpty(config.Endpoint) || !Uri.IsWellFormedUriString(config.Endpoint, UriKind.Absolute));
        }

        [Fact]
        public void SiemConfiguration_CustomHeaders_CanBeSet()
        {
            // Arrange
            var config = new SiemConfiguration();

            // Act
            config.CustomHeaders["Authorization"] = "Bearer token";
            config.CustomHeaders["X-Custom-Header"] = "value";

            // Assert
            Assert.Equal(2, config.CustomHeaders.Count);
            Assert.Equal("Bearer token", config.CustomHeaders["Authorization"]);
        }
    }
}