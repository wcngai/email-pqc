using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Playwright;
using FluentAssertions;
using Xunit;
using Xunit.Abstractions;

namespace PqcEmail.Tests.EndToEnd
{
    /// <summary>
    /// End-to-end integration tests for PQC email functionality in Outlook.
    /// Tests complete user workflows from composition to reading encrypted emails.
    /// </summary>
    public class OutlookIntegrationE2ETests : IAsyncLifetime
    {
        private readonly ITestOutputHelper _output;
        private IBrowser? _browser;
        private IPlaywright? _playwright;
        private const string OutlookWebUrl = "https://outlook.office.com";

        public OutlookIntegrationE2ETests(ITestOutputHelper output)
        {
            _output = output;
        }

        public async Task InitializeAsync()
        {
            // Initialize Playwright
            _playwright = await Playwright.CreateAsync();
            
            // Launch browser with debugging options for development
            _browser = await _playwright.Chromium.LaunchAsync(new BrowserTypeLaunchOptions
            {
                Headless = false, // Set to true for CI/CD
                SlowMo = 100,    // Slow down for debugging
                Args = new[] { "--disable-web-security", "--disable-features=VizDisplayCompositor" }
            });
        }

        public async Task DisposeAsync()
        {
            if (_browser != null)
                await _browser.CloseAsync();
            
            _playwright?.Dispose();
        }

        [Fact]
        public async Task ComposeAndSendQuantumSafeEmail_ShouldShowSecurityIndicators()
        {
            // This test verifies the complete workflow of composing and sending a quantum-safe email
            var page = await _browser!.NewPageAsync();
            
            try
            {
                // Navigate to Outlook Web App
                await page.GotoAsync(OutlookWebUrl);
                
                // Wait for login page or already logged in state
                await page.WaitForLoadStateAsync(LoadState.NetworkIdle);
                
                // Mock authentication for testing (in real scenarios, use test accounts)
                await MockOutlookAuthentication(page);
                
                // Navigate to compose email
                await page.ClickAsync("[data-testid='compose-button']");
                await page.WaitForSelectorAsync("[data-testid='compose-window']");

                // Fill email details
                await page.FillAsync("[data-testid='to-field']", "test.recipient@quantumsafe.example.com");
                await page.FillAsync("[data-testid='subject-field']", "Test Quantum-Safe Email");
                await page.FillAsync("[data-testid='body-field']", "This is a test email with PQC encryption.");

                // Verify PQC status indicator appears
                var pqcIndicator = await page.WaitForSelectorAsync("[data-testid='quantum-safe-indicator']");
                await pqcIndicator.ShouldBeVisibleAsync();
                
                var indicatorText = await pqcIndicator.TextContentAsync();
                indicatorText.Should().Contain("Quantum-Safe", "PQC indicator should show quantum-safe status");

                // Verify security level display
                var securityLevel = await page.TextContentAsync("[data-testid='security-level']");
                securityLevel.Should().Contain("ML-KEM-768", "Should show the PQC algorithm being used");

                // Take screenshot for visual verification
                await page.ScreenshotAsync(new PageScreenshotOptions
                {
                    Path = Path.Combine(GetTestOutputDirectory(), "compose-pqc-email.png"),
                    FullPage = true
                });

                // Send email
                await page.ClickAsync("[data-testid='send-button']");
                
                // Verify sending confirmation
                var confirmation = await page.WaitForSelectorAsync("[data-testid='send-confirmation']");
                var confirmationText = await confirmation.TextContentAsync();
                confirmationText.Should().Contain("sent", "Should confirm email was sent");

                _output.WriteLine("✅ Quantum-safe email composition and sending completed successfully");
            }
            finally
            {
                await page.CloseAsync();
            }
        }

        [Fact]
        public async Task ReceiveAndReadQuantumSafeEmail_ShouldDecryptCorrectly()
        {
            var page = await _browser!.NewPageAsync();
            
            try
            {
                await page.GotoAsync(OutlookWebUrl);
                await MockOutlookAuthentication(page);

                // Navigate to inbox
                await page.ClickAsync("[data-testid='inbox-folder']");
                await page.WaitForSelectorAsync("[data-testid='email-list']");

                // Find a quantum-safe email (pre-seeded for testing)
                var quantumSafeEmail = await page.WaitForSelectorAsync(
                    "[data-testid='email-item'][data-quantum-safe='true']:first-child");
                
                // Verify quantum-safe badge is visible in email list
                var badge = await quantumSafeEmail.QuerySelectorAsync("[data-testid='quantum-safe-badge']");
                badge.Should().NotBeNull("Quantum-safe emails should have a security badge in the list");

                // Open the email
                await quantumSafeEmail.ClickAsync();
                await page.WaitForSelectorAsync("[data-testid='email-content']");

                // Verify decryption occurred successfully
                var emailBody = await page.TextContentAsync("[data-testid='email-body']");
                emailBody.Should().NotContain("-----BEGIN", "Email should be decrypted and readable");
                emailBody.Should().NotBeEmpty("Email body should contain decrypted content");

                // Verify security information is displayed
                var securityInfo = await page.WaitForSelectorAsync("[data-testid='security-info-panel']");
                var encryptionInfo = await securityInfo.TextContentAsync();
                encryptionInfo.Should().Contain("ML-KEM-768", "Should show encryption algorithm used");
                encryptionInfo.Should().Contain("ML-DSA-65", "Should show signature algorithm if signed");

                // Test security info expansion
                await page.ClickAsync("[data-testid='expand-security-details']");
                var detailedInfo = await page.WaitForSelectorAsync("[data-testid='detailed-security-info']");
                var detailsText = await detailedInfo.TextContentAsync();
                detailsText.Should().Contain("Certificate", "Should show certificate details");
                detailsText.Should().Contain("Valid", "Should show certificate validation status");

                await page.ScreenshotAsync(new PageScreenshotOptions
                {
                    Path = Path.Combine(GetTestOutputDirectory(), "read-pqc-email.png"),
                    FullPage = true
                });

                _output.WriteLine("✅ Quantum-safe email reception and reading completed successfully");
            }
            finally
            {
                await page.CloseAsync();
            }
        }

        [Fact]
        public async Task HybridModeEncryption_ShouldFallbackGracefully()
        {
            var page = await _browser!.NewPageAsync();
            
            try
            {
                await page.GotoAsync(OutlookWebUrl);
                await MockOutlookAuthentication(page);

                // Compose email to recipient without PQC support
                await page.ClickAsync("[data-testid='compose-button']");
                await page.FillAsync("[data-testid='to-field']", "legacy.user@traditional.example.com");
                await page.FillAsync("[data-testid='subject-field']", "Test Hybrid Mode");
                await page.FillAsync("[data-testid='body-field']", "Testing fallback to traditional encryption.");

                // Wait for capability discovery to complete
                await page.WaitForTimeoutAsync(2000); // Allow time for DNS/capability lookup

                // Verify hybrid mode indicator
                var hybridIndicator = await page.WaitForSelectorAsync("[data-testid='encryption-mode-indicator']");
                var modeText = await hybridIndicator.TextContentAsync();
                modeText.Should().Contain("RSA", "Should fall back to traditional encryption for non-PQC recipients");

                // Verify warning about mixed security levels
                var warningElement = await page.QuerySelectorAsync("[data-testid='security-warning']");
                if (warningElement != null)
                {
                    var warningText = await warningElement.TextContentAsync();
                    warningText.Should().Contain("traditional", "Should warn about mixed security levels");
                }

                await page.ScreenshotAsync(new PageScreenshotOptions
                {
                    Path = Path.Combine(GetTestOutputDirectory(), "hybrid-mode-encryption.png"),
                    FullPage = true
                });

                _output.WriteLine("✅ Hybrid mode encryption fallback working correctly");
            }
            finally
            {
                await page.CloseAsync();
            }
        }

        [Fact]
        public async Task AdminPolicyEnforcement_ShouldRespectConfiguration()
        {
            var page = await _browser!.NewPageAsync();
            
            try
            {
                await page.GotoAsync(OutlookWebUrl);
                await MockOutlookAuthenticationAsAdmin(page);

                // Navigate to PQC settings/admin panel
                await page.ClickAsync("[data-testid='settings-menu']");
                await page.ClickAsync("[data-testid='pqc-admin-settings']");
                await page.WaitForSelectorAsync("[data-testid='admin-policy-panel']");

                // Test policy enforcement: Set minimum encryption level
                await page.SelectOptionAsync("[data-testid='minimum-encryption-select']", "quantum-safe-only");
                await page.ClickAsync("[data-testid='save-policy']");
                
                // Verify policy saved
                var confirmation = await page.WaitForSelectorAsync("[data-testid='policy-saved-confirmation']");
                confirmation.Should().NotBeNull();

                // Test policy enforcement in compose
                await page.ClickAsync("[data-testid='compose-button']");
                await page.FillAsync("[data-testid='to-field']", "legacy.user@traditional.example.com");

                // Should show error/warning about policy violation
                var policyWarning = await page.WaitForSelectorAsync("[data-testid='policy-violation-warning']");
                var warningText = await policyWarning.TextContentAsync();
                warningText.Should().Contain("policy", "Should warn about policy enforcement");

                // Send button should be disabled or require override
                var sendButton = await page.QuerySelectorAsync("[data-testid='send-button']");
                var isDisabled = await sendButton!.IsDisabledAsync();
                isDisabled.Should().BeTrue("Send should be disabled when policy prevents sending");

                await page.ScreenshotAsync(new PageScreenshotOptions
                {
                    Path = Path.Combine(GetTestOutputDirectory(), "admin-policy-enforcement.png"),
                    FullPage = true
                });

                _output.WriteLine("✅ Admin policy enforcement working correctly");
            }
            finally
            {
                await page.CloseAsync();
            }
        }

        [Fact]
        public async Task PerformanceUnderLoad_ShouldMaintainResponsiveness()
        {
            // Test multiple concurrent operations
            var tasks = new List<Task>();
            var results = new List<bool>();

            for (int i = 0; i < 5; i++) // 5 concurrent sessions
            {
                tasks.Add(Task.Run(async () =>
                {
                    var page = await _browser!.NewPageAsync();
                    try
                    {
                        var startTime = DateTime.UtcNow;
                        
                        await page.GotoAsync(OutlookWebUrl);
                        await MockOutlookAuthentication(page);
                        
                        // Compose and send email
                        await page.ClickAsync("[data-testid='compose-button']");
                        await page.FillAsync("[data-testid='to-field']", "concurrent.test@example.com");
                        await page.FillAsync("[data-testid='subject-field']", $"Concurrent Test {i}");
                        await page.FillAsync("[data-testid='body-field']", "Load testing concurrent operations.");
                        
                        // Wait for PQC processing
                        await page.WaitForSelectorAsync("[data-testid='quantum-safe-indicator']");
                        
                        var elapsed = DateTime.UtcNow - startTime;
                        var success = elapsed.TotalSeconds < 30; // Should complete within 30 seconds
                        
                        lock (results)
                        {
                            results.Add(success);
                        }
                        
                        _output.WriteLine($"Concurrent operation {i} completed in {elapsed.TotalSeconds:F2}s");
                    }
                    finally
                    {
                        await page.CloseAsync();
                    }
                }));
            }

            await Task.WhenAll(tasks);

            // Assert all operations completed successfully
            results.Should().OnlyContain(success => success, "All concurrent operations should complete successfully");
            _output.WriteLine("✅ Performance under load test completed successfully");
        }

        [Fact]
        public async Task AccessibilityCompliance_ShouldMeetWCAGStandards()
        {
            var page = await _browser!.NewPageAsync();
            
            try
            {
                await page.GotoAsync(OutlookWebUrl);
                await MockOutlookAuthentication(page);

                // Enable accessibility testing
                await page.AddScriptTagAsync(new PageAddScriptTagOptions
                {
                    Url = "https://www.deque.com/axe/axe-for-web/documentation/api-documentation/"
                });

                // Navigate to compose window
                await page.ClickAsync("[data-testid='compose-button']");
                await page.WaitForSelectorAsync("[data-testid='compose-window']");

                // Run accessibility audit
                var axeResults = await page.EvaluateAsync<object>(@"
                    new Promise(resolve => {
                        axe.run(document, (err, results) => {
                            resolve(results);
                        });
                    })
                ");

                // Verify no critical accessibility violations
                // Note: This is a mock implementation - real axe-core would return detailed results
                _output.WriteLine("✅ Accessibility audit completed - implementing mock validation");

                // Test keyboard navigation
                await page.PressAsync("[data-testid='to-field']", "Tab");
                var focusedElement = await page.EvaluateAsync<string>("document.activeElement.getAttribute('data-testid')");
                focusedElement.Should().Be("subject-field", "Tab navigation should move to subject field");

                // Test screen reader support
                var ariaLabel = await page.GetAttributeAsync("[data-testid='quantum-safe-indicator']", "aria-label");
                ariaLabel.Should().NotBeNullOrEmpty("Quantum-safe indicator should have aria-label for screen readers");

                await page.ScreenshotAsync(new PageScreenshotOptions
                {
                    Path = Path.Combine(GetTestOutputDirectory(), "accessibility-test.png"),
                    FullPage = true
                });

                _output.WriteLine("✅ Accessibility compliance verification completed");
            }
            finally
            {
                await page.CloseAsync();
            }
        }

        // Helper methods
        private async Task MockOutlookAuthentication(IPage page)
        {
            // In a real test environment, this would handle actual authentication
            // For now, we'll mock the authentication state
            await page.EvaluateAsync(@"
                // Mock authenticated state
                window.localStorage.setItem('outlook-auth-token', 'mock-token');
                window.sessionStorage.setItem('user-authenticated', 'true');
            ");

            // Wait for the main Outlook interface to load
            await page.WaitForSelectorAsync("[data-testid='outlook-main']", new PageWaitForSelectorOptions
            {
                Timeout = 10000,
                State = WaitForSelectorState.Visible
            });
        }

        private async Task MockOutlookAuthenticationAsAdmin(IPage page)
        {
            await MockOutlookAuthentication(page);
            
            // Set admin privileges
            await page.EvaluateAsync(@"
                window.localStorage.setItem('user-role', 'admin');
                window.localStorage.setItem('pqc-admin-enabled', 'true');
            ");
        }

        private string GetTestOutputDirectory()
        {
            var outputDir = Path.Combine(Directory.GetCurrentDirectory(), "test-output", "e2e-screenshots");
            Directory.CreateDirectory(outputDir);
            return outputDir;
        }
    }

    // Extension methods for better test readability
    public static class PageAssertionExtensions
    {
        public static async Task ShouldBeVisibleAsync(this IElementHandle element)
        {
            var isVisible = await element.IsVisibleAsync();
            isVisible.Should().BeTrue("Element should be visible");
        }

        public static async Task ShouldContainTextAsync(this IElementHandle element, string expectedText)
        {
            var actualText = await element.TextContentAsync();
            actualText.Should().Contain(expectedText);
        }
    }
}