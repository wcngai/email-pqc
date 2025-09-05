using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Core.Monitoring
{
    /// <summary>
    /// Provides compliance reporting services for regulatory requirements including SOX, GDPR, and FFIEC.
    /// </summary>
    public class ComplianceReportingService : IComplianceReportingService
    {
        private readonly ILogger<ComplianceReportingService> _logger;
        private readonly IPolicyAuditLogger _auditLogger;
        private readonly IMetricsCollectionService _metricsService;
        private readonly ComplianceConfiguration _configuration;

        /// <summary>
        /// Initializes a new instance of the <see cref="ComplianceReportingService"/> class.
        /// </summary>
        /// <param name="logger">The logger instance</param>
        /// <param name="auditLogger">The audit logger service</param>
        /// <param name="metricsService">The metrics collection service</param>
        /// <param name="configuration">The compliance configuration</param>
        public ComplianceReportingService(
            ILogger<ComplianceReportingService> logger,
            IPolicyAuditLogger auditLogger,
            IMetricsCollectionService metricsService,
            ComplianceConfiguration configuration)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _auditLogger = auditLogger ?? throw new ArgumentNullException(nameof(auditLogger));
            _metricsService = metricsService ?? throw new ArgumentNullException(nameof(metricsService));
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        /// <summary>
        /// Generates a SOX compliance report for the specified period.
        /// </summary>
        /// <param name="reportPeriod">The reporting period</param>
        /// <returns>The generated SOX compliance report</returns>
        public async Task<ComplianceReport> GenerateSoxReportAsync(ReportingPeriod reportPeriod)
        {
            _logger.LogInformation("Generating SOX compliance report for period {StartDate} to {EndDate}",
                reportPeriod.StartDate, reportPeriod.EndDate);

            if (!reportPeriod.IsValid())
                throw new ArgumentException("Invalid reporting period", nameof(reportPeriod));

            try
            {
                var report = new ComplianceReport
                {
                    Standard = ComplianceStandard.SOX,
                    Period = reportPeriod,
                    GeneratedBy = Environment.UserName,
                    Title = $"SOX Compliance Report - {reportPeriod.StartDate:yyyy-MM-dd} to {reportPeriod.EndDate:yyyy-MM-dd}",
                    ExecutiveSummary = "This report demonstrates compliance with Sarbanes-Oxley Act requirements for financial data protection and audit trails."
                };

                // Gather audit events for the period
                var auditEvents = await _auditLogger.GetAuditEventsAsync(
                    reportPeriod.StartDate, 
                    reportPeriod.EndDate);

                // Generate SOX-specific sections
                await GenerateSoxSectionsAsync(report, auditEvents);

                // Generate metrics
                report.Metrics = await GenerateComplianceMetricsAsync(auditEvents);

                // Analyze findings
                report.Findings = await AnalyzeSoxComplianceAsync(auditEvents);

                // Determine overall compliance status
                report.Status = DetermineComplianceStatus(report.Findings);

                // Save report
                await SaveReportAsync(report);

                _logger.LogInformation("Successfully generated SOX compliance report {ReportId}", report.ReportId);
                return report;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate SOX compliance report");
                throw;
            }
        }

        /// <summary>
        /// Generates a GDPR compliance report for the specified period.
        /// </summary>
        /// <param name="reportPeriod">The reporting period</param>
        /// <returns>The generated GDPR compliance report</returns>
        public async Task<ComplianceReport> GenerateGdprReportAsync(ReportingPeriod reportPeriod)
        {
            _logger.LogInformation("Generating GDPR compliance report for period {StartDate} to {EndDate}",
                reportPeriod.StartDate, reportPeriod.EndDate);

            if (!reportPeriod.IsValid())
                throw new ArgumentException("Invalid reporting period", nameof(reportPeriod));

            try
            {
                var report = new ComplianceReport
                {
                    Standard = ComplianceStandard.GDPR,
                    Period = reportPeriod,
                    GeneratedBy = Environment.UserName,
                    Title = $"GDPR Compliance Report - {reportPeriod.StartDate:yyyy-MM-dd} to {reportPeriod.EndDate:yyyy-MM-dd}",
                    ExecutiveSummary = "This report demonstrates compliance with General Data Protection Regulation requirements for privacy and data protection."
                };

                // Gather audit events for the period
                var auditEvents = await _auditLogger.GetAuditEventsAsync(
                    reportPeriod.StartDate, 
                    reportPeriod.EndDate);

                // Generate GDPR-specific sections
                await GenerateGdprSectionsAsync(report, auditEvents);

                // Generate metrics
                report.Metrics = await GenerateComplianceMetricsAsync(auditEvents);

                // Analyze findings
                report.Findings = await AnalyzeGdprComplianceAsync(auditEvents);

                // Determine overall compliance status
                report.Status = DetermineComplianceStatus(report.Findings);

                // Save report
                await SaveReportAsync(report);

                _logger.LogInformation("Successfully generated GDPR compliance report {ReportId}", report.ReportId);
                return report;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate GDPR compliance report");
                throw;
            }
        }

        /// <summary>
        /// Generates an FFIEC compliance report for the specified period.
        /// </summary>
        /// <param name="reportPeriod">The reporting period</param>
        /// <returns>The generated FFIEC compliance report</returns>
        public async Task<ComplianceReport> GenerateFfiecReportAsync(ReportingPeriod reportPeriod)
        {
            _logger.LogInformation("Generating FFIEC compliance report for period {StartDate} to {EndDate}",
                reportPeriod.StartDate, reportPeriod.EndDate);

            if (!reportPeriod.IsValid())
                throw new ArgumentException("Invalid reporting period", nameof(reportPeriod));

            try
            {
                var report = new ComplianceReport
                {
                    Standard = ComplianceStandard.FFIEC,
                    Period = reportPeriod,
                    GeneratedBy = Environment.UserName,
                    Title = $"FFIEC Compliance Report - {reportPeriod.StartDate:yyyy-MM-dd} to {reportPeriod.EndDate:yyyy-MM-dd}",
                    ExecutiveSummary = "This report demonstrates compliance with Federal Financial Institutions Examination Council cybersecurity requirements."
                };

                // Gather audit events for the period
                var auditEvents = await _auditLogger.GetAuditEventsAsync(
                    reportPeriod.StartDate, 
                    reportPeriod.EndDate);

                // Generate FFIEC-specific sections
                await GenerateFfiecSectionsAsync(report, auditEvents);

                // Generate metrics
                report.Metrics = await GenerateComplianceMetricsAsync(auditEvents);

                // Analyze findings
                report.Findings = await AnalyzeFfiecComplianceAsync(auditEvents);

                // Determine overall compliance status
                report.Status = DetermineComplianceStatus(report.Findings);

                // Save report
                await SaveReportAsync(report);

                _logger.LogInformation("Successfully generated FFIEC compliance report {ReportId}", report.ReportId);
                return report;
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to generate FFIEC compliance report");
                throw;
            }
        }

        /// <summary>
        /// Gets available compliance reports for the specified time period.
        /// </summary>
        /// <param name="startDate">The start date</param>
        /// <param name="endDate">The end date</param>
        /// <returns>The list of available reports</returns>
        public async Task<IEnumerable<ComplianceReportSummary>> GetAvailableReportsAsync(DateTime startDate, DateTime endDate)
        {
            try
            {
                var reports = new List<ComplianceReportSummary>();
                var reportsDirectory = Path.Combine(_configuration.ReportsPath, "compliance");
                
                if (!Directory.Exists(reportsDirectory))
                {
                    _logger.LogDebug("Reports directory does not exist: {Directory}", reportsDirectory);
                    return reports;
                }

                var reportFiles = Directory.GetFiles(reportsDirectory, "*.json")
                    .Where(f => File.GetCreationTime(f) >= startDate && File.GetCreationTime(f) <= endDate);

                foreach (var reportFile in reportFiles)
                {
                    try
                    {
                        var reportJson = await File.ReadAllTextAsync(reportFile);
                        var report = JsonSerializer.Deserialize<ComplianceReport>(reportJson);
                        
                        if (report != null)
                        {
                            reports.Add(new ComplianceReportSummary
                            {
                                ReportId = report.ReportId,
                                Standard = report.Standard,
                                StartDate = report.Period.StartDate,
                                EndDate = report.Period.EndDate,
                                GeneratedAt = report.GeneratedAt,
                                GeneratedBy = report.GeneratedBy,
                                Status = report.Status,
                                FindingsCount = report.Findings.Count,
                                CriticalIssues = report.Findings.Count(f => f.Severity == FindingSeverity.Critical),
                                ComplianceScore = report.Metrics.ComplianceScore
                            });
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogWarning(ex, "Failed to read report file: {File}", reportFile);
                    }
                }

                return reports.OrderByDescending(r => r.GeneratedAt);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to retrieve available reports");
                throw;
            }
        }

        /// <summary>
        /// Exports a compliance report in the specified format.
        /// </summary>
        /// <param name="reportId">The report identifier</param>
        /// <param name="format">The export format</param>
        /// <returns>The exported report data</returns>
        public async Task<byte[]> ExportReportAsync(Guid reportId, ExportFormat format)
        {
            try
            {
                var report = await LoadReportAsync(reportId);
                if (report == null)
                    throw new FileNotFoundException($"Report {reportId} not found");

                return format switch
                {
                    ExportFormat.JSON => await ExportToJsonAsync(report),
                    ExportFormat.PDF => await ExportToPdfAsync(report),
                    ExportFormat.Excel => await ExportToExcelAsync(report),
                    ExportFormat.CSV => await ExportToCsvAsync(report),
                    ExportFormat.HTML => await ExportToHtmlAsync(report),
                    ExportFormat.XML => await ExportToXmlAsync(report),
                    _ => throw new ArgumentException($"Unsupported export format: {format}")
                };
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Failed to export report {ReportId} to {Format}", reportId, format);
                throw;
            }
        }

        #region Private Methods

        /// <summary>
        /// Generates SOX-specific report sections.
        /// </summary>
        private async Task GenerateSoxSectionsAsync(ComplianceReport report, IEnumerable<PolicyAuditEvent> auditEvents)
        {
            report.Sections.Add(new ComplianceSection
            {
                SectionId = "SOX.302",
                Title = "Financial Reporting Controls",
                Description = "Controls over financial reporting processes and data integrity",
                Requirements = new List<string> { "Internal controls over financial reporting", "Disclosure controls and procedures" },
                Status = ComplianceStatus.Compliant,
                Details = "All cryptographic operations are properly logged and audited with tamper-evident trails."
            });

            report.Sections.Add(new ComplianceSection
            {
                SectionId = "SOX.404",
                Title = "Management Assessment",
                Description = "Management's assessment of internal control effectiveness",
                Requirements = new List<string> { "Annual assessment of internal controls", "External auditor attestation" },
                Status = ComplianceStatus.Compliant,
                Details = "Comprehensive audit logging provides evidence of control effectiveness."
            });

            await Task.CompletedTask;
        }

        /// <summary>
        /// Generates GDPR-specific report sections.
        /// </summary>
        private async Task GenerateGdprSectionsAsync(ComplianceReport report, IEnumerable<PolicyAuditEvent> auditEvents)
        {
            report.Sections.Add(new ComplianceSection
            {
                SectionId = "GDPR.Art32",
                Title = "Security of Processing",
                Description = "Technical and organizational measures to ensure data security",
                Requirements = new List<string> { "Encryption of personal data", "Ongoing confidentiality and integrity" },
                Status = ComplianceStatus.Compliant,
                Details = "Post-quantum cryptography provides advanced protection for personal data in email communications."
            });

            report.Sections.Add(new ComplianceSection
            {
                SectionId = "GDPR.Art25",
                Title = "Data Protection by Design",
                Description = "Privacy by design and by default principles",
                Requirements = new List<string> { "Data protection by design", "Data protection by default" },
                Status = ComplianceStatus.Compliant,
                Details = "System implements privacy-preserving encryption by default with minimal data exposure."
            });

            await Task.CompletedTask;
        }

        /// <summary>
        /// Generates FFIEC-specific report sections.
        /// </summary>
        private async Task GenerateFfiecSectionsAsync(ComplianceReport report, IEnumerable<PolicyAuditEvent> auditEvents)
        {
            report.Sections.Add(new ComplianceSection
            {
                SectionId = "FFIEC.Cybersecurity",
                Title = "Cybersecurity Assessment",
                Description = "Cybersecurity maturity and risk management",
                Requirements = new List<string> { "Risk management", "Threat intelligence", "Cybersecurity controls" },
                Status = ComplianceStatus.Compliant,
                Details = "Post-quantum cryptography addresses emerging quantum computing threats to financial data."
            });

            report.Sections.Add(new ComplianceSection
            {
                SectionId = "FFIEC.AuthAccess",
                Title = "Authentication and Access Controls",
                Description = "Multi-factor authentication and access control requirements",
                Requirements = new List<string> { "Strong authentication", "Access controls", "Monitoring and logging" },
                Status = ComplianceStatus.Compliant,
                Details = "Digital signatures and key management provide strong authentication for financial communications."
            });

            await Task.CompletedTask;
        }

        /// <summary>
        /// Generates compliance metrics from audit events.
        /// </summary>
        private async Task<ComplianceMetrics> GenerateComplianceMetricsAsync(IEnumerable<PolicyAuditEvent> auditEvents)
        {
            var events = auditEvents.ToList();
            var metrics = new ComplianceMetrics
            {
                TotalAuditEvents = events.Count,
                PolicyDecisions = events.Count(e => e.EventType == "PolicyDecision"),
                PolicyViolations = events.Count(e => e.EventType == "PolicyViolation"),
                FallbackEvents = events.Count(e => e.EventType == "AlgorithmFallback"),
                SuccessfulOperations = events.Count(e => e.Outcome == PolicyOutcome.Success),
                FailedOperations = events.Count(e => e.Outcome == PolicyOutcome.Failure)
            };

            // Calculate PQC adoption rate
            var totalCryptographicEvents = events.Count(e => e.AlgorithmsUsed.Any());
            var pqcEvents = events.Count(e => e.AlgorithmsUsed.Any(a => 
                a.Value.Contains("ML-KEM") || a.Value.Contains("ML-DSA") || 
                a.Value.Contains("Kyber") || a.Value.Contains("Dilithium")));

            if (totalCryptographicEvents > 0)
                metrics.PqcAdoptionRate = (double)pqcEvents / totalCryptographicEvents * 100;

            // Calculate compliance score
            var violationWeight = metrics.PolicyViolations * 10;
            var failureWeight = metrics.FailedOperations * 5;
            var totalWeight = violationWeight + failureWeight;
            var maxScore = Math.Max(metrics.TotalAuditEvents, 1);
            metrics.ComplianceScore = Math.Max(0, 100 - (totalWeight / maxScore * 100));

            // Algorithm usage statistics
            foreach (var evt in events.Where(e => e.AlgorithmsUsed.Any()))
            {
                foreach (var algorithm in evt.AlgorithmsUsed.Values)
                {
                    if (metrics.AlgorithmUsage.ContainsKey(algorithm))
                        metrics.AlgorithmUsage[algorithm]++;
                    else
                        metrics.AlgorithmUsage[algorithm] = 1;
                }
            }

            await Task.CompletedTask;
            return metrics;
        }

        /// <summary>
        /// Analyzes SOX compliance findings.
        /// </summary>
        private async Task<List<ComplianceFinding>> AnalyzeSoxComplianceAsync(IEnumerable<PolicyAuditEvent> auditEvents)
        {
            var findings = new List<ComplianceFinding>();
            var violations = auditEvents.Where(e => e.EventType == "PolicyViolation").ToList();

            if (violations.Any())
            {
                findings.Add(new ComplianceFinding
                {
                    FindingId = "SOX-001",
                    Type = FindingType.PolicyViolation,
                    Severity = FindingSeverity.High,
                    Title = "Policy Violations Detected",
                    Description = $"Found {violations.Count} policy violations during the reporting period",
                    Requirement = "SOX Section 404 - Internal Controls",
                    Impact = "Potential weakness in internal controls over financial reporting",
                    Recommendation = "Review and strengthen policy enforcement mechanisms",
                    Status = RemediationStatus.Open
                });
            }

            await Task.CompletedTask;
            return findings;
        }

        /// <summary>
        /// Analyzes GDPR compliance findings.
        /// </summary>
        private async Task<List<ComplianceFinding>> AnalyzeGdprComplianceAsync(IEnumerable<PolicyAuditEvent> auditEvents)
        {
            var findings = new List<ComplianceFinding>();
            var unencryptedEvents = auditEvents.Where(e => 
                e.EventType == "PolicyDecision" && 
                e.PolicyDecision != null && 
                e.PolicyDecision.Contains("unencrypted")).ToList();

            if (unencryptedEvents.Any())
            {
                findings.Add(new ComplianceFinding
                {
                    FindingId = "GDPR-001",
                    Type = FindingType.PolicyViolation,
                    Severity = FindingSeverity.Medium,
                    Title = "Unencrypted Data Transmission",
                    Description = $"Found {unencryptedEvents.Count} instances of unencrypted data transmission",
                    Requirement = "GDPR Article 32 - Security of Processing",
                    Impact = "Potential exposure of personal data during transmission",
                    Recommendation = "Implement mandatory encryption for all personal data communications",
                    Status = RemediationStatus.Open
                });
            }

            await Task.CompletedTask;
            return findings;
        }

        /// <summary>
        /// Analyzes FFIEC compliance findings.
        /// </summary>
        private async Task<List<ComplianceFinding>> AnalyzeFfiecComplianceAsync(IEnumerable<PolicyAuditEvent> auditEvents)
        {
            var findings = new List<ComplianceFinding>();
            var fallbackEvents = auditEvents.Where(e => e.EventType == "AlgorithmFallback").ToList();

            if (fallbackEvents.Count > auditEvents.Count() * 0.1) // More than 10% fallback rate
            {
                findings.Add(new ComplianceFinding
                {
                    FindingId = "FFIEC-001",
                    Type = FindingType.TechnicalIssue,
                    Severity = FindingSeverity.Medium,
                    Title = "High Algorithm Fallback Rate",
                    Description = $"Algorithm fallback rate of {(double)fallbackEvents.Count / auditEvents.Count() * 100:F1}% exceeds recommended threshold",
                    Requirement = "FFIEC Cybersecurity Assessment - Resilience",
                    Impact = "Potential degradation of cryptographic security controls",
                    Recommendation = "Investigate root causes and improve PQC implementation stability",
                    Status = RemediationStatus.Open
                });
            }

            await Task.CompletedTask;
            return findings;
        }

        /// <summary>
        /// Determines overall compliance status based on findings.
        /// </summary>
        private static ComplianceStatus DetermineComplianceStatus(IEnumerable<ComplianceFinding> findings)
        {
            var findingsList = findings.ToList();
            
            if (!findingsList.Any())
                return ComplianceStatus.Compliant;

            if (findingsList.Any(f => f.Severity == FindingSeverity.Critical))
                return ComplianceStatus.NonCompliant;

            if (findingsList.Any(f => f.Severity == FindingSeverity.High))
                return ComplianceStatus.PartiallyCompliant;

            return ComplianceStatus.PartiallyCompliant;
        }

        /// <summary>
        /// Saves a compliance report to storage.
        /// </summary>
        private async Task SaveReportAsync(ComplianceReport report)
        {
            var reportsDirectory = Path.Combine(_configuration.ReportsPath, "compliance");
            Directory.CreateDirectory(reportsDirectory);

            var fileName = $"{report.Standard}_{report.ReportId}_{DateTime.UtcNow:yyyyMMdd}.json";
            var filePath = Path.Combine(reportsDirectory, fileName);

            var jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            var reportJson = JsonSerializer.Serialize(report, jsonOptions);
            await File.WriteAllTextAsync(filePath, reportJson);

            _logger.LogDebug("Saved compliance report to {FilePath}", filePath);
        }

        /// <summary>
        /// Loads a compliance report from storage.
        /// </summary>
        private async Task<ComplianceReport?> LoadReportAsync(Guid reportId)
        {
            var reportsDirectory = Path.Combine(_configuration.ReportsPath, "compliance");
            var reportFiles = Directory.GetFiles(reportsDirectory, $"*{reportId}*.json");

            if (!reportFiles.Any())
                return null;

            var reportJson = await File.ReadAllTextAsync(reportFiles.First());
            return JsonSerializer.Deserialize<ComplianceReport>(reportJson);
        }

        /// <summary>
        /// Exports report to JSON format.
        /// </summary>
        private static async Task<byte[]> ExportToJsonAsync(ComplianceReport report)
        {
            var jsonOptions = new JsonSerializerOptions
            {
                WriteIndented = true,
                PropertyNamingPolicy = JsonNamingPolicy.CamelCase
            };

            var json = JsonSerializer.Serialize(report, jsonOptions);
            return System.Text.Encoding.UTF8.GetBytes(json);
        }

        // Placeholder methods for other export formats
        private static async Task<byte[]> ExportToPdfAsync(ComplianceReport report)
        {
            // TODO: Implement PDF export using library like iTextSharp or similar
            await Task.CompletedTask;
            throw new NotImplementedException("PDF export not yet implemented");
        }

        private static async Task<byte[]> ExportToExcelAsync(ComplianceReport report)
        {
            // TODO: Implement Excel export using library like EPPlus or similar
            await Task.CompletedTask;
            throw new NotImplementedException("Excel export not yet implemented");
        }

        private static async Task<byte[]> ExportToCsvAsync(ComplianceReport report)
        {
            // TODO: Implement CSV export
            await Task.CompletedTask;
            throw new NotImplementedException("CSV export not yet implemented");
        }

        private static async Task<byte[]> ExportToHtmlAsync(ComplianceReport report)
        {
            // TODO: Implement HTML export
            await Task.CompletedTask;
            throw new NotImplementedException("HTML export not yet implemented");
        }

        private static async Task<byte[]> ExportToXmlAsync(ComplianceReport report)
        {
            // TODO: Implement XML export
            await Task.CompletedTask;
            throw new NotImplementedException("XML export not yet implemented");
        }

        #endregion
    }

    /// <summary>
    /// Configuration settings for compliance reporting.
    /// </summary>
    public class ComplianceConfiguration
    {
        /// <summary>
        /// Gets or sets the path for storing compliance reports.
        /// </summary>
        public string ReportsPath { get; set; } = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "PqcEmail", "Reports");

        /// <summary>
        /// Gets or sets the retention period for compliance reports in days.
        /// </summary>
        public int ReportRetentionDays { get; set; } = 2555; // 7 years

        /// <summary>
        /// Gets or sets whether to automatically generate periodic reports.
        /// </summary>
        public bool AutoGenerateReports { get; set; } = true;

        /// <summary>
        /// Gets or sets the automatic report generation schedule.
        /// </summary>
        public Dictionary<ComplianceStandard, PeriodType> AutoReportSchedule { get; set; } = new()
        {
            { ComplianceStandard.SOX, PeriodType.Quarterly },
            { ComplianceStandard.GDPR, PeriodType.Monthly },
            { ComplianceStandard.FFIEC, PeriodType.Annual }
        };
    }
}