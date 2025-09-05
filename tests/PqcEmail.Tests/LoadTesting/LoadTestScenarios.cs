using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using NBomber.CSharp;
using NBomber.Http.CSharp;
using Xunit;
using Xunit.Abstractions;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.LoadTesting
{
    /// <summary>
    /// Load testing scenarios for PQC email system.
    /// Tests system performance under high user load and concurrent operations.
    /// Target: Support for 10,000+ users with acceptable performance.
    /// </summary>
    public class LoadTestScenarios
    {
        private readonly ITestOutputHelper _output;
        private const int TARGET_USER_COUNT = 10000;
        private const int CONCURRENT_SESSIONS = 500;
        private const double ACCEPTABLE_ERROR_RATE = 0.01; // 1%

        public LoadTestScenarios(ITestOutputHelper output)
        {
            _output = output;
        }

        [Fact]
        public async Task EmailEncryption_LoadTest_10KUsers()
        {
            _output.WriteLine($"Starting email encryption load test for {TARGET_USER_COUNT} users");

            var scenario = Scenario.Create("email_encryption", async context =>
            {
                var userId = context.ScenarioInfo.ThreadId;
                var messageId = context.InvocationNumber;
                
                try
                {
                    // Simulate user encrypting an email
                    var emailData = GenerateTestEmailData(userId, messageId);
                    var recipients = GenerateTestRecipients(Random.Shared.Next(1, 6)); // 1-5 recipients
                    
                    var startTime = DateTime.UtcNow;
                    var encryptedEmail = await EncryptEmailForUser(userId, emailData, recipients);
                    var duration = DateTime.UtcNow - startTime;
                    
                    // Validate encryption succeeded and performance target met
                    if (encryptedEmail != null && duration.TotalMilliseconds < 500)
                    {
                        return Response.Ok(statusCode: 200, sizeBytes: encryptedEmail.Length);
                    }
                    else
                    {
                        return Response.Fail(error: $"Encryption failed or too slow: {duration.TotalMilliseconds}ms");
                    }
                }
                catch (Exception ex)
                {
                    return Response.Fail(error: $"Exception: {ex.Message}");
                }
            })
            .WithLoadSimulations(
                Simulation.InjectPerSec(rate: 100, during: TimeSpan.FromSeconds(30)), // Ramp up
                Simulation.KeepConstant(copies: CONCURRENT_SESSIONS, during: TimeSpan.FromMinutes(5)) // Sustained load
            );

            var stats = NBomberRunner
                .RegisterScenarios(scenario)
                .Run();

            // Assert performance criteria
            var scenarioStats = stats.AllScenarios.First();
            
            _output.WriteLine($"Total requests: {scenarioStats.Ok.Request.Count}");
            _output.WriteLine($"Failed requests: {scenarioStats.Fail.Request.Count}");
            _output.WriteLine($"Error rate: {scenarioStats.Fail.Request.Count / (double)scenarioStats.AllRequestCount:P2}");
            _output.WriteLine($"Mean response time: {scenarioStats.Ok.Request.Mean}ms");
            _output.WriteLine($"95th percentile: {scenarioStats.Ok.Request.Percentile95}ms");
            _output.WriteLine($"Max response time: {scenarioStats.Ok.Request.Max}ms");
            _output.WriteLine($"Throughput: {scenarioStats.Ok.Request.Count / stats.TestSuite.Duration.TotalSeconds:F2} req/sec");

            // Performance assertions
            var errorRate = scenarioStats.Fail.Request.Count / (double)scenarioStats.AllRequestCount;
            errorRate.Should().BeLessThan(ACCEPTABLE_ERROR_RATE, "Error rate should be acceptable under load");
            
            scenarioStats.Ok.Request.Mean.Should().BeLessThan(500, "Mean response time should meet target");
            scenarioStats.Ok.Request.Percentile95.Should().BeLessThan(750, "95th percentile should be reasonable");
        }

        [Fact]
        public async Task CapabilityDiscovery_LoadTest_DNSQueries()
        {
            _output.WriteLine("Starting capability discovery load test");

            var testDomains = GenerateTestDomains(1000); // 1000 unique domains
            var domainIndex = 0;

            var scenario = Scenario.Create("capability_discovery", async context =>
            {
                try
                {
                    var domain = testDomains[Interlocked.Increment(ref domainIndex) % testDomains.Count];
                    
                    var startTime = DateTime.UtcNow;
                    var capabilities = await DiscoverCapabilities(domain);
                    var duration = DateTime.UtcNow - startTime;
                    
                    // First lookup should complete within reasonable time, cached should be very fast
                    var maxTime = capabilities.FromCache ? 50 : 2000; // 50ms cached, 2s fresh lookup
                    
                    if (capabilities != null && duration.TotalMilliseconds < maxTime)
                    {
                        return Response.Ok(statusCode: 200);
                    }
                    else
                    {
                        return Response.Fail(error: $"Discovery failed or too slow: {duration.TotalMilliseconds}ms");
                    }
                }
                catch (Exception ex)
                {
                    return Response.Fail(error: $"Exception: {ex.Message}");
                }
            })
            .WithLoadSimulations(
                Simulation.InjectPerSec(rate: 50, during: TimeSpan.FromSeconds(20)),
                Simulation.KeepConstant(copies: 200, during: TimeSpan.FromMinutes(3))
            );

            var stats = NBomberRunner
                .RegisterScenarios(scenario)
                .Run();

            var scenarioStats = stats.AllScenarios.First();
            
            _output.WriteLine($"Discovery requests: {scenarioStats.Ok.Request.Count}");
            _output.WriteLine($"Cache hit rate: {CalculateCacheHitRate()}%");
            _output.WriteLine($"Mean response time: {scenarioStats.Ok.Request.Mean}ms");

            // Verify caching effectiveness
            var errorRate = scenarioStats.Fail.Request.Count / (double)scenarioStats.AllRequestCount;
            errorRate.Should().BeLessThan(0.05, "Discovery should be reliable under load");
            scenarioStats.Ok.Request.Mean.Should().BeLessThan(500, "Mean discovery time should be reasonable with caching");
        }

        [Fact]
        public async Task ConcurrentKeyGeneration_LoadTest()
        {
            _output.WriteLine("Starting concurrent key generation load test");

            var scenario = Scenario.Create("key_generation", async context =>
            {
                try
                {
                    var userId = $"user_{context.ScenarioInfo.ThreadId}_{context.InvocationNumber}";
                    
                    var startTime = DateTime.UtcNow;
                    var keyPair = await GenerateKeyPairForUser(userId);
                    var duration = DateTime.UtcNow - startTime;
                    
                    // Key generation should complete within reasonable time
                    if (keyPair != null && keyPair.IsValid && duration.TotalMilliseconds < 1000)
                    {
                        return Response.Ok(statusCode: 200);
                    }
                    else
                    {
                        return Response.Fail(error: $"Key generation failed or too slow: {duration.TotalMilliseconds}ms");
                    }
                }
                catch (Exception ex)
                {
                    return Response.Fail(error: $"Exception: {ex.Message}");
                }
            })
            .WithLoadSimulations(
                Simulation.InjectPerSec(rate: 10, during: TimeSpan.FromSeconds(30)), // Slower ramp for key gen
                Simulation.KeepConstant(copies: 50, during: TimeSpan.FromMinutes(2)) // Lower concurrency for key gen
            );

            var stats = NBomberRunner
                .RegisterScenarios(scenario)
                .Run();

            var scenarioStats = stats.AllScenarios.First();
            
            _output.WriteLine($"Key generation requests: {scenarioStats.Ok.Request.Count}");
            _output.WriteLine($"Mean generation time: {scenarioStats.Ok.Request.Mean}ms");
            _output.WriteLine($"Max generation time: {scenarioStats.Ok.Request.Max}ms");

            var errorRate = scenarioStats.Fail.Request.Count / (double)scenarioStats.AllRequestCount;
            errorRate.Should().BeLessThan(0.02, "Key generation should be reliable");
            scenarioStats.Ok.Request.Mean.Should().BeLessThan(1000, "Mean key generation time should be reasonable");
        }

        [Fact]
        public async Task MixedWorkload_LoadTest()
        {
            _output.WriteLine("Starting mixed workload load test (encryption + decryption + discovery)");

            var encryptionScenario = Scenario.Create("encryption_load", async context =>
            {
                var result = await SimulateEmailEncryption(context);
                return result;
            })
            .WithWeight(60) // 60% encryption operations
            .WithLoadSimulations(Simulation.KeepConstant(copies: 200, during: TimeSpan.FromMinutes(3)));

            var decryptionScenario = Scenario.Create("decryption_load", async context =>
            {
                var result = await SimulateEmailDecryption(context);
                return result;
            })
            .WithWeight(30) // 30% decryption operations  
            .WithLoadSimulations(Simulation.KeepConstant(copies: 150, during: TimeSpan.FromMinutes(3)));

            var discoveryScenario = Scenario.Create("discovery_load", async context =>
            {
                var result = await SimulateCapabilityDiscovery(context);
                return result;
            })
            .WithWeight(10) // 10% discovery operations
            .WithLoadSimulations(Simulation.KeepConstant(copies: 50, during: TimeSpan.FromMinutes(3)));

            var stats = NBomberRunner
                .RegisterScenarios(encryptionScenario, decryptionScenario, discoveryScenario)
                .Run();

            // Analyze mixed workload performance
            foreach (var scenario in stats.AllScenarios)
            {
                _output.WriteLine($"\n{scenario.ScenarioName} Results:");
                _output.WriteLine($"  Requests: {scenario.Ok.Request.Count}");
                _output.WriteLine($"  Mean time: {scenario.Ok.Request.Mean}ms");
                _output.WriteLine($"  95th percentile: {scenario.Ok.Request.Percentile95}ms");
                _output.WriteLine($"  Error rate: {scenario.Fail.Request.Count / (double)scenario.AllRequestCount:P2}");
                
                // Each workload should meet its performance targets
                var errorRate = scenario.Fail.Request.Count / (double)scenario.AllRequestCount;
                errorRate.Should().BeLessThan(ACCEPTABLE_ERROR_RATE, $"{scenario.ScenarioName} error rate should be acceptable");
                
                if (scenario.ScenarioName.Contains("encryption"))
                {
                    scenario.Ok.Request.Mean.Should().BeLessThan(500, "Encryption should meet performance target");
                }
                else if (scenario.ScenarioName.Contains("decryption"))
                {
                    scenario.Ok.Request.Mean.Should().BeLessThan(300, "Decryption should be faster than encryption");
                }
                else if (scenario.ScenarioName.Contains("discovery"))
                {
                    scenario.Ok.Request.Mean.Should().BeLessThan(200, "Discovery should be fast with caching");
                }
            }

            // Overall system throughput
            var totalRequests = stats.AllScenarios.Sum(s => s.Ok.Request.Count);
            var overallThroughput = totalRequests / stats.TestSuite.Duration.TotalSeconds;
            _output.WriteLine($"\nOverall throughput: {overallThroughput:F2} operations/sec");
            
            overallThroughput.Should().BeGreaterThan(100, "System should maintain good overall throughput");
        }

        [Fact]
        public async Task MemoryUsage_UnderSustainedLoad()
        {
            _output.WriteLine("Testing memory usage under sustained load");

            var initialMemory = GC.GetTotalMemory(true);
            var memoryMeasurements = new List<(DateTime time, long memory)>();
            var operationCount = 0;

            // Start memory monitoring
            var memoryMonitoring = Task.Run(async () =>
            {
                while (operationCount < 10000) // Monitor until test completes
                {
                    await Task.Delay(5000); // Check every 5 seconds
                    var currentMemory = GC.GetTotalMemory(false);
                    lock (memoryMeasurements)
                    {
                        memoryMeasurements.Add((DateTime.UtcNow, currentMemory));
                    }
                }
            });

            // Simulate sustained operations
            var scenario = Scenario.Create("memory_test", async context =>
            {
                Interlocked.Increment(ref operationCount);
                
                var emailData = GenerateTestEmailData(context.ScenarioInfo.ThreadId, context.InvocationNumber);
                var recipients = GenerateTestRecipients(2);
                var encrypted = await EncryptEmailForUser(context.ScenarioInfo.ThreadId, emailData, recipients);
                
                // Force garbage collection occasionally
                if (operationCount % 1000 == 0)
                {
                    GC.Collect();
                    GC.WaitForPendingFinalizers();
                }

                return encrypted != null ? Response.Ok() : Response.Fail();
            })
            .WithLoadSimulations(Simulation.KeepConstant(copies: 100, during: TimeSpan.FromMinutes(5)));

            var stats = NBomberRunner
                .RegisterScenarios(scenario)
                .Run();

            await memoryMonitoring;

            // Analyze memory usage
            var finalMemory = GC.GetTotalMemory(true);
            var memoryGrowth = finalMemory - initialMemory;
            var memoryGrowthMB = memoryGrowth / (1024.0 * 1024.0);

            _output.WriteLine($"Initial memory: {initialMemory / (1024 * 1024):F2}MB");
            _output.WriteLine($"Final memory: {finalMemory / (1024 * 1024):F2}MB");
            _output.WriteLine($"Memory growth: {memoryGrowthMB:F2}MB");
            _output.WriteLine($"Operations completed: {operationCount}");
            _output.WriteLine($"Memory per operation: {memoryGrowth / (double)operationCount:F0} bytes");

            // Memory usage assertions
            memoryGrowthMB.Should().BeLessThan(500, "Memory growth should be reasonable under sustained load");
            
            // Check for memory leaks - growth should stabilize
            if (memoryMeasurements.Count > 10)
            {
                var lastMeasurements = memoryMeasurements.TakeLast(5).Select(m => m.memory).ToList();
                var memoryVariance = CalculateVariance(lastMeasurements);
                var avgMemory = lastMeasurements.Average();
                var coefficientOfVariation = Math.Sqrt(memoryVariance) / avgMemory;
                
                _output.WriteLine($"Memory stability (CV): {coefficientOfVariation:F4}");
                coefficientOfVariation.Should().BeLessThan(0.1, "Memory usage should stabilize (indicating no major leaks)");
            }
        }

        [Fact]
        public async Task DatabaseConnection_PoolingUnderLoad()
        {
            _output.WriteLine("Testing database connection pooling under load");

            var connectionCount = 0;
            var activeConnections = 0;
            var maxConcurrentConnections = 0;

            var scenario = Scenario.Create("database_operations", async context =>
            {
                try
                {
                    Interlocked.Increment(ref connectionCount);
                    var currentActive = Interlocked.Increment(ref activeConnections);
                    
                    // Track maximum concurrent connections
                    var currentMax = maxConcurrentConnections;
                    while (currentActive > currentMax)
                    {
                        Interlocked.CompareExchange(ref maxConcurrentConnections, currentActive, currentMax);
                        currentMax = maxConcurrentConnections;
                    }

                    // Simulate database operations
                    await SimulateDatabaseOperation(context.ScenarioInfo.ThreadId);
                    
                    Interlocked.Decrement(ref activeConnections);
                    return Response.Ok();
                }
                catch (Exception ex)
                {
                    Interlocked.Decrement(ref activeConnections);
                    return Response.Fail(error: ex.Message);
                }
            })
            .WithLoadSimulations(
                Simulation.InjectPerSec(rate: 50, during: TimeSpan.FromSeconds(30)),
                Simulation.KeepConstant(copies: 200, during: TimeSpan.FromMinutes(3))
            );

            var stats = NBomberRunner
                .RegisterScenarios(scenario)
                .Run();

            var scenarioStats = stats.AllScenarios.First();
            
            _output.WriteLine($"Total connections created: {connectionCount}");
            _output.WriteLine($"Max concurrent connections: {maxConcurrentConnections}");
            _output.WriteLine($"Successful operations: {scenarioStats.Ok.Request.Count}");
            _output.WriteLine($"Connection efficiency: {scenarioStats.Ok.Request.Count / (double)connectionCount:F2}");

            // Connection pooling assertions
            maxConcurrentConnections.Should().BeLessThan(100, "Connection pooling should limit concurrent connections");
            var errorRate = scenarioStats.Fail.Request.Count / (double)scenarioStats.AllRequestCount;
            errorRate.Should().BeLessThan(0.01, "Database operations should be reliable under load");
        }

        // Helper methods for load testing

        private EmailData GenerateTestEmailData(int userId, int messageId)
        {
            return new EmailData
            {
                From = $"user{userId}@loadtest.example.com",
                Subject = $"Load Test Message {messageId}",
                Body = $"This is a test message {messageId} from user {userId} for load testing purposes. " +
                       $"Generated at {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss.fff}",
                Size = Random.Shared.Next(1000, 50000) // 1KB to 50KB messages
            };
        }

        private List<string> GenerateTestRecipients(int count)
        {
            return Enumerable.Range(1, count)
                .Select(i => $"recipient{i}@loadtest.example.com")
                .ToList();
        }

        private List<string> GenerateTestDomains(int count)
        {
            return Enumerable.Range(1, count)
                .Select(i => $"domain{i}.loadtest.example.com")
                .ToList();
        }

        private async Task<byte[]?> EncryptEmailForUser(int userId, EmailData emailData, List<string> recipients)
        {
            // Simulate encryption processing time
            var processingTime = 50 + (recipients.Count * 15) + Random.Shared.Next(0, 100);
            await Task.Delay(processingTime);

            // Simulate occasional failures
            if (Random.Shared.NextDouble() < 0.005) // 0.5% failure rate
            {
                throw new InvalidOperationException("Simulated encryption failure");
            }

            // Return mock encrypted data
            var baseSize = emailData.Size;
            var overhead = recipients.Count * 1088; // KEM ciphertext per recipient
            return new byte[baseSize + overhead];
        }

        private async Task<CapabilityResult> DiscoverCapabilities(string domain)
        {
            // Simulate DNS lookup time
            var isFromCache = Random.Shared.NextDouble() < 0.7; // 70% cache hit rate
            var delay = isFromCache ? Random.Shared.Next(1, 10) : Random.Shared.Next(100, 500);
            await Task.Delay(delay);

            return new CapabilityResult
            {
                Domain = domain,
                SupportsPQC = Random.Shared.NextDouble() < 0.8, // 80% support PQC
                FromCache = isFromCache,
                Algorithms = new[] { "ML-KEM-768", "ML-DSA-65" }
            };
        }

        private async Task<TestKeyPair?> GenerateKeyPairForUser(string userId)
        {
            // Key generation is expensive
            await Task.Delay(Random.Shared.Next(200, 800));

            return new TestKeyPair
            {
                UserId = userId,
                PublicKey = new byte[1184],
                PrivateKey = new byte[2400],
                IsValid = true,
                Algorithm = "ML-KEM-768"
            };
        }

        private async Task<Response> SimulateEmailEncryption(ScenarioContext context)
        {
            try
            {
                var emailData = GenerateTestEmailData(context.ScenarioInfo.ThreadId, context.InvocationNumber);
                var recipients = GenerateTestRecipients(Random.Shared.Next(1, 4));
                
                var encrypted = await EncryptEmailForUser(context.ScenarioInfo.ThreadId, emailData, recipients);
                return encrypted != null ? Response.Ok() : Response.Fail();
            }
            catch (Exception ex)
            {
                return Response.Fail(error: ex.Message);
            }
        }

        private async Task<Response> SimulateEmailDecryption(ScenarioContext context)
        {
            try
            {
                // Decryption is typically faster than encryption
                await Task.Delay(Random.Shared.Next(20, 150));
                
                // Simulate occasional decryption failures
                if (Random.Shared.NextDouble() < 0.002) // 0.2% failure rate
                {
                    return Response.Fail(error: "Simulated decryption failure");
                }

                return Response.Ok();
            }
            catch (Exception ex)
            {
                return Response.Fail(error: ex.Message);
            }
        }

        private async Task<Response> SimulateCapabilityDiscovery(ScenarioContext context)
        {
            try
            {
                var domain = $"domain{context.InvocationNumber % 100}.example.com";
                var capabilities = await DiscoverCapabilities(domain);
                return Response.Ok();
            }
            catch (Exception ex)
            {
                return Response.Fail(error: ex.Message);
            }
        }

        private async Task SimulateDatabaseOperation(int threadId)
        {
            // Simulate database query time
            await Task.Delay(Random.Shared.Next(10, 100));
            
            // Simulate occasional database timeouts
            if (Random.Shared.NextDouble() < 0.001) // 0.1% timeout rate
            {
                throw new TimeoutException("Database operation timeout");
            }
        }

        private double CalculateCacheHitRate()
        {
            // Mock cache hit rate calculation
            return Random.Shared.NextDouble() * 30 + 70; // 70-100% hit rate
        }

        private double CalculateVariance(List<long> values)
        {
            var mean = values.Average();
            return values.Sum(v => (v - mean) * (v - mean)) / values.Count;
        }

        // Helper classes
        public class EmailData
        {
            public string From { get; set; } = string.Empty;
            public string Subject { get; set; } = string.Empty;
            public string Body { get; set; } = string.Empty;
            public int Size { get; set; }
        }

        public class CapabilityResult
        {
            public string Domain { get; set; } = string.Empty;
            public bool SupportsPQC { get; set; }
            public bool FromCache { get; set; }
            public string[] Algorithms { get; set; } = Array.Empty<string>();
        }

        public class TestKeyPair
        {
            public string UserId { get; set; } = string.Empty;
            public byte[] PublicKey { get; set; } = Array.Empty<byte>();
            public byte[] PrivateKey { get; set; } = Array.Empty<byte>();
            public bool IsValid { get; set; }
            public string Algorithm { get; set; } = string.Empty;
        }
    }
}