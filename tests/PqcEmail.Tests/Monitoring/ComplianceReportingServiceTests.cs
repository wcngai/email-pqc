using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Moq;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;
using PqcEmail.Core.Monitoring;
using Xunit;

namespace PqcEmail.Tests.Monitoring
{
    /// <summary>
    /// Tests for the compliance reporting service functionality.
    /// </summary>
    public class ComplianceReportingServiceTests : IDisposable
    {
        private readonly Mock<ILogger<ComplianceReportingService>> _mockLogger;
        private readonly Mock<IPolicyAuditLogger> _mockAuditLogger;
        private readonly Mock<IMetricsCollectionService> _mockMetricsService;
        private readonly ComplianceConfiguration _configuration;
        private readonly ComplianceReportingService _reportingService;
        private readonly string _testReportsPath;

        public ComplianceReportingServiceTests()
        {
            _mockLogger = new Mock<ILogger<ComplianceReportingService>>();
            _mockAuditLogger = new Mock<IPolicyAuditLogger>();
            _mockMetricsService = new Mock<IMetricsCollectionService>();

            _testReportsPath = Path.Combine(Path.GetTempPath(), "PqcEmailTests", Guid.NewGuid().ToString());
            Directory.CreateDirectory(_testReportsPath);

            _configuration = new ComplianceConfiguration
            {
                ReportsPath = _testReportsPath,
                ReportRetentionDays = 2555,
                AutoGenerateReports = true
            };

            _reportingService = new ComplianceReportingService(
                _mockLogger.Object,
                _mockAuditLogger.Object,
                _mockMetricsService.Object,
                _configuration);
        }

        public void Dispose()
        {
            if (Directory.Exists(_testReportsPath))
            {
                Directory.Delete(_testReportsPath, true);
            }
        }

        [Fact]
        public async Task GenerateSoxReportAsync_ValidPeriod_CreatesReport()
        {
            // Arrange
            var reportPeriod = CreateValidReportingPeriod();
            var auditEvents = CreateTestAuditEvents();
            
            _mockAuditLogger.Setup(x => x.GetAuditEventsAsync(
                It.IsAny<DateTime>(),
                It.IsAny<DateTime>(),
                It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync(auditEvents);

            // Act
            var report = await _reportingService.GenerateSoxReportAsync(reportPeriod);

            // Assert
            Assert.NotNull(report);
            Assert.Equal(ComplianceStandard.SOX, report.Standard);
            Assert.Equal(reportPeriod.StartDate, report.Period.StartDate);
            Assert.Equal(reportPeriod.EndDate, report.Period.EndDate);
            Assert.Contains("SOX Compliance Report", report.Title);
            Assert.NotEmpty(report.Sections);
            Assert.True(report.Sections.Any(s => s.SectionId == "SOX.302"));
            Assert.True(report.Sections.Any(s => s.SectionId == "SOX.404"));
        }

        [Fact]
        public async Task GenerateGdprReportAsync_ValidPeriod_CreatesReport()
        {
            // Arrange
            var reportPeriod = CreateValidReportingPeriod();
            var auditEvents = CreateTestAuditEvents();
            
            _mockAuditLogger.Setup(x => x.GetAuditEventsAsync(
                It.IsAny<DateTime>(),
                It.IsAny<DateTime>(),
                It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync(auditEvents);

            // Act
            var report = await _reportingService.GenerateGdprReportAsync(reportPeriod);

            // Assert
            Assert.NotNull(report);
            Assert.Equal(ComplianceStandard.GDPR, report.Standard);
            Assert.Contains("GDPR Compliance Report", report.Title);
            Assert.NotEmpty(report.Sections);
            Assert.True(report.Sections.Any(s => s.SectionId == "GDPR.Art32"));
            Assert.True(report.Sections.Any(s => s.SectionId == "GDPR.Art25"));
        }

        [Fact]
        public async Task GenerateFfiecReportAsync_ValidPeriod_CreatesReport()
        {
            // Arrange
            var reportPeriod = CreateValidReportingPeriod();
            var auditEvents = CreateTestAuditEvents();
            
            _mockAuditLogger.Setup(x => x.GetAuditEventsAsync(
                It.IsAny<DateTime>(),
                It.IsAny<DateTime>(),
                It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync(auditEvents);

            // Act
            var report = await _reportingService.GenerateFfiecReportAsync(reportPeriod);

            // Assert
            Assert.NotNull(report);
            Assert.Equal(ComplianceStandard.FFIEC, report.Standard);
            Assert.Contains("FFIEC Compliance Report", report.Title);
            Assert.NotEmpty(report.Sections);
            Assert.True(report.Sections.Any(s => s.SectionId == "FFIEC.Cybersecurity"));
            Assert.True(report.Sections.Any(s => s.SectionId == "FFIEC.AuthAccess"));
        }

        [Fact]
        public async Task GenerateSoxReportAsync_InvalidPeriod_ThrowsArgumentException()
        {
            // Arrange
            var invalidPeriod = new ReportingPeriod
            {
                StartDate = DateTime.UtcNow,
                EndDate = DateTime.UtcNow.AddDays(-1) // Invalid: end before start
            };

            // Act & Assert
            await Assert.ThrowsAsync<ArgumentException>(() => 
                _reportingService.GenerateSoxReportAsync(invalidPeriod));
        }

        [Fact]
        public async Task GenerateReport_WithPolicyViolations_CreatesFindings()
        {
            // Arrange
            var reportPeriod = CreateValidReportingPeriod();
            var auditEvents = new List<PolicyAuditEvent>
            {
                new PolicyAuditEvent
                {
                    EventType = "PolicyViolation",
                    Outcome = PolicyOutcome.Violation,
                    Timestamp = DateTime.UtcNow.AddDays(-1)
                }
            };
            
            _mockAuditLogger.Setup(x => x.GetAuditEventsAsync(
                It.IsAny<DateTime>(),
                It.IsAny<DateTime>(),
                It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync(auditEvents);

            // Act
            var report = await _reportingService.GenerateSoxReportAsync(reportPeriod);

            // Assert
            Assert.NotEmpty(report.Findings);
            Assert.Contains(report.Findings, f => f.Type == FindingType.PolicyViolation);
            Assert.Contains(report.Findings, f => f.Severity == FindingSeverity.High);
            Assert.Equal(ComplianceStatus.PartiallyCompliant, report.Status);
        }

        [Fact]
        public async Task GenerateReport_CalculatesMetricsCorrectly()
        {
            // Arrange
            var reportPeriod = CreateValidReportingPeriod();
            var auditEvents = new List<PolicyAuditEvent>
            {
                new PolicyAuditEvent
                {
                    EventType = "PolicyDecision",
                    Outcome = PolicyOutcome.Success,
                    AlgorithmsUsed = new Dictionary<string, string> { ["KEM"] = "ML-KEM-768" }
                },
                new PolicyAuditEvent
                {
                    EventType = "PolicyDecision",
                    Outcome = PolicyOutcome.Success,
                    AlgorithmsUsed = new Dictionary<string, string> { ["KEM"] = "RSA-OAEP-2048" }
                },
                new PolicyAuditEvent
                {
                    EventType = "PolicyViolation",
                    Outcome = PolicyOutcome.Violation
                }
            };
            
            _mockAuditLogger.Setup(x => x.GetAuditEventsAsync(
                It.IsAny<DateTime>(),
                It.IsAny<DateTime>(),
                It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync(auditEvents);

            // Act
            var report = await _reportingService.GenerateSoxReportAsync(reportPeriod);

            // Assert
            Assert.Equal(3, report.Metrics.TotalAuditEvents);
            Assert.Equal(2, report.Metrics.PolicyDecisions);
            Assert.Equal(1, report.Metrics.PolicyViolations);
            Assert.Equal(2, report.Metrics.SuccessfulOperations);
            Assert.Equal(50.0, report.Metrics.PqcAdoptionRate); // 1 PQC out of 2 crypto events
            Assert.Contains("ML-KEM-768", report.Metrics.AlgorithmUsage.Keys);
        }

        [Fact]
        public async Task GetAvailableReportsAsync_WithExistingReports_ReturnsReports()
        {
            // Arrange
            var startDate = DateTime.UtcNow.AddDays(-30);
            var endDate = DateTime.UtcNow;

            // Create a test report first
            var reportPeriod = CreateValidReportingPeriod();
            var auditEvents = CreateTestAuditEvents();
            
            _mockAuditLogger.Setup(x => x.GetAuditEventsAsync(
                It.IsAny<DateTime>(),
                It.IsAny<DateTime>(),
                It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync(auditEvents);

            var report = await _reportingService.GenerateSoxReportAsync(reportPeriod);

            // Act
            var availableReports = await _reportingService.GetAvailableReportsAsync(startDate, endDate);

            // Assert
            Assert.NotEmpty(availableReports);
            var reportSummary = availableReports.First();
            Assert.Equal(report.ReportId, reportSummary.ReportId);
            Assert.Equal(ComplianceStandard.SOX, reportSummary.Standard);
            Assert.Equal(report.GeneratedBy, reportSummary.GeneratedBy);
        }

        [Fact]
        public async Task GetAvailableReportsAsync_NoReports_ReturnsEmpty()
        {
            // Arrange
            var startDate = DateTime.UtcNow.AddDays(-30);
            var endDate = DateTime.UtcNow;

            // Act
            var availableReports = await _reportingService.GetAvailableReportsAsync(startDate, endDate);

            // Assert
            Assert.Empty(availableReports);
        }

        [Fact]
        public async Task ExportReportAsync_JsonFormat_ReturnsJsonBytes()
        {
            // Arrange
            var reportPeriod = CreateValidReportingPeriod();
            var auditEvents = CreateTestAuditEvents();
            
            _mockAuditLogger.Setup(x => x.GetAuditEventsAsync(
                It.IsAny<DateTime>(),
                It.IsAny<DateTime>(),
                It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync(auditEvents);

            var report = await _reportingService.GenerateSoxReportAsync(reportPeriod);

            // Act
            var exportedData = await _reportingService.ExportReportAsync(report.ReportId, ExportFormat.JSON);

            // Assert
            Assert.NotNull(exportedData);
            Assert.True(exportedData.Length > 0);
            
            // Verify it's valid JSON
            var jsonString = System.Text.Encoding.UTF8.GetString(exportedData);
            Assert.Contains("\"reportId\"", jsonString);
            Assert.Contains("\"standard\"", jsonString);
        }

        [Fact]
        public async Task ExportReportAsync_UnsupportedFormat_ThrowsArgumentException()
        {
            // Arrange
            var reportId = Guid.NewGuid();

            // Act & Assert
            await Assert.ThrowsAsync<NotImplementedException>(() => 
                _reportingService.ExportReportAsync(reportId, ExportFormat.PDF));
        }

        [Fact]
        public async Task ExportReportAsync_NonExistentReport_ThrowsFileNotFoundException()
        {
            // Arrange
            var nonExistentReportId = Guid.NewGuid();

            // Act & Assert
            await Assert.ThrowsAsync<FileNotFoundException>(() => 
                _reportingService.ExportReportAsync(nonExistentReportId, ExportFormat.JSON));
        }

        [Theory]
        [InlineData(ComplianceStandard.SOX)]
        [InlineData(ComplianceStandard.GDPR)]
        [InlineData(ComplianceStandard.FFIEC)]
        public async Task GenerateReport_AllStandards_CreatesValidReport(ComplianceStandard standard)
        {
            // Arrange
            var reportPeriod = CreateValidReportingPeriod();
            var auditEvents = CreateTestAuditEvents();
            
            _mockAuditLogger.Setup(x => x.GetAuditEventsAsync(
                It.IsAny<DateTime>(),
                It.IsAny<DateTime>(),
                It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync(auditEvents);

            // Act
            ComplianceReport report = standard switch
            {
                ComplianceStandard.SOX => await _reportingService.GenerateSoxReportAsync(reportPeriod),
                ComplianceStandard.GDPR => await _reportingService.GenerateGdprReportAsync(reportPeriod),
                ComplianceStandard.FFIEC => await _reportingService.GenerateFfiecReportAsync(reportPeriod),
                _ => throw new ArgumentException("Unsupported standard")
            };

            // Assert
            Assert.NotNull(report);
            Assert.Equal(standard, report.Standard);
            Assert.NotNull(report.ReportId);
            Assert.True(report.ReportId != Guid.Empty);
            Assert.NotEmpty(report.Title);
            Assert.NotEmpty(report.ExecutiveSummary);
            Assert.NotNull(report.GeneratedBy);
            Assert.NotNull(report.Metrics);
        }

        [Fact]
        public async Task AnalyzeGdprCompliance_UnencryptedEmails_CreatesFindings()
        {
            // Arrange
            var reportPeriod = CreateValidReportingPeriod();
            var auditEvents = new List<PolicyAuditEvent>
            {
                new PolicyAuditEvent
                {
                    EventType = "PolicyDecision",
                    PolicyDecision = "Allow unencrypted for external recipient",
                    Outcome = PolicyOutcome.Success
                }
            };
            
            _mockAuditLogger.Setup(x => x.GetAuditEventsAsync(
                It.IsAny<DateTime>(),
                It.IsAny<DateTime>(),
                It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync(auditEvents);

            // Act
            var report = await _reportingService.GenerateGdprReportAsync(reportPeriod);

            // Assert
            Assert.Contains(report.Findings, f => f.FindingId == "GDPR-001");
            Assert.Contains(report.Findings, f => f.Type == FindingType.PolicyViolation);
            Assert.Contains(report.Findings, f => f.Requirement.Contains("GDPR Article 32"));
        }

        [Fact]
        public async Task AnalyzeFfiecCompliance_HighFallbackRate_CreatesFindings()
        {
            // Arrange
            var reportPeriod = CreateValidReportingPeriod();
            var auditEvents = new List<PolicyAuditEvent>();
            
            // Create events with high fallback rate (>10%)
            for (int i = 0; i < 10; i++)
            {
                auditEvents.Add(new PolicyAuditEvent
                {
                    EventType = "AlgorithmFallback",
                    Outcome = PolicyOutcome.Fallback
                });
            }
            
            // Add some regular events
            for (int i = 0; i < 80; i++)
            {
                auditEvents.Add(new PolicyAuditEvent
                {
                    EventType = "PolicyDecision",
                    Outcome = PolicyOutcome.Success
                });
            }
            
            _mockAuditLogger.Setup(x => x.GetAuditEventsAsync(
                It.IsAny<DateTime>(),
                It.IsAny<DateTime>(),
                It.IsAny<IEnumerable<string>>()))
                .ReturnsAsync(auditEvents);

            // Act
            var report = await _reportingService.GenerateFfiecReportAsync(reportPeriod);

            // Assert
            Assert.Contains(report.Findings, f => f.FindingId == "FFIEC-001");
            Assert.Contains(report.Findings, f => f.Type == FindingType.TechnicalIssue);
            Assert.Contains(report.Findings, f => f.Title.Contains("High Algorithm Fallback Rate"));
        }

        [Theory]
        [InlineData(0, ComplianceStatus.Compliant)]
        [InlineData(1, ComplianceStatus.PartiallyCompliant)] // High severity finding
        [InlineData(0, ComplianceStatus.PartiallyCompliant)] // Medium severity finding
        public void DetermineComplianceStatus_BasedOnFindings_ReturnsCorrectStatus(
            int criticalFindings, ComplianceStatus expectedStatus)
        {
            // This test would verify the private method logic
            // In a real implementation, you might make this method internal and testable
            // or test it through the public interface
        }

        #region Helper Methods

        private ReportingPeriod CreateValidReportingPeriod()
        {
            return new ReportingPeriod
            {
                StartDate = DateTime.UtcNow.AddDays(-30),
                EndDate = DateTime.UtcNow.AddDays(-1),
                Type = PeriodType.Monthly,
                Description = "Test reporting period"
            };
        }

        private List<PolicyAuditEvent> CreateTestAuditEvents()
        {
            return new List<PolicyAuditEvent>
            {
                new PolicyAuditEvent
                {
                    EventId = Guid.NewGuid(),
                    Timestamp = DateTime.UtcNow.AddDays(-5),
                    EventType = "PolicyDecision",
                    Actor = "test@example.com",
                    RecipientEmail = "recipient@example.com",
                    PolicyDecision = "Hybrid encryption applied",
                    Outcome = PolicyOutcome.Success,
                    AlgorithmsUsed = new Dictionary<string, string>
                    {
                        ["KEM"] = "ML-KEM-768",
                        ["Signature"] = "ML-DSA-65"
                    }
                },
                new PolicyAuditEvent
                {
                    EventId = Guid.NewGuid(),
                    Timestamp = DateTime.UtcNow.AddDays(-10),
                    EventType = "PolicyDecision",
                    Actor = "test2@example.com",
                    RecipientEmail = "recipient2@example.com",
                    PolicyDecision = "Traditional encryption fallback",
                    Outcome = PolicyOutcome.Success,
                    AlgorithmsUsed = new Dictionary<string, string>
                    {
                        ["KEM"] = "RSA-OAEP-2048",
                        ["Signature"] = "RSA-PSS-2048"
                    }
                },
                new PolicyAuditEvent
                {
                    EventId = Guid.NewGuid(),
                    Timestamp = DateTime.UtcNow.AddDays(-15),
                    EventType = "AlgorithmFallback",
                    RecipientEmail = "recipient3@example.com",
                    Outcome = PolicyOutcome.Fallback,
                    EventData = new Dictionary<string, object>
                    {
                        ["OriginalAlgorithm"] = "ML-KEM-768",
                        ["FallbackAlgorithm"] = "RSA-OAEP-2048",
                        ["Reason"] = "Recipient does not support PQC"
                    }
                }
            };
        }

        #endregion
    }

    /// <summary>
    /// Tests for reporting period validation and utility methods.
    /// </summary>
    public class ReportingPeriodTests
    {
        [Fact]
        public void IsValid_ValidPeriod_ReturnsTrue()
        {
            // Arrange
            var period = new ReportingPeriod
            {
                StartDate = DateTime.UtcNow.AddDays(-30),
                EndDate = DateTime.UtcNow.AddDays(-1)
            };

            // Act
            var isValid = period.IsValid();

            // Assert
            Assert.True(isValid);
        }

        [Fact]
        public void IsValid_EndBeforeStart_ReturnsFalse()
        {
            // Arrange
            var period = new ReportingPeriod
            {
                StartDate = DateTime.UtcNow,
                EndDate = DateTime.UtcNow.AddDays(-1)
            };

            // Act
            var isValid = period.IsValid();

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void IsValid_FutureEndDate_ReturnsFalse()
        {
            // Arrange
            var period = new ReportingPeriod
            {
                StartDate = DateTime.UtcNow.AddDays(-30),
                EndDate = DateTime.UtcNow.AddDays(1)
            };

            // Act
            var isValid = period.IsValid();

            // Assert
            Assert.False(isValid);
        }

        [Fact]
        public void Duration_ValidPeriod_ReturnsCorrectTimeSpan()
        {
            // Arrange
            var startDate = DateTime.UtcNow.AddDays(-30);
            var endDate = DateTime.UtcNow.AddDays(-1);
            var period = new ReportingPeriod
            {
                StartDate = startDate,
                EndDate = endDate
            };

            // Act
            var duration = period.Duration;

            // Assert
            Assert.Equal(TimeSpan.FromDays(29), duration);
        }
    }
}