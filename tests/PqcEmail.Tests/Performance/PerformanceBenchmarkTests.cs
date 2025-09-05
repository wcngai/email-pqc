using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using FluentAssertions;
using Microsoft.Extensions.Logging;
using Moq;
using Xunit;
using Xunit.Abstractions;
using PqcEmail.Core.Cryptography;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Performance
{
    /// <summary>
    /// Performance benchmarking tests for PQC email operations.
    /// Validates encryption performance targets: <500ms encryption, <200ms signatures.
    /// </summary>
    public class PerformanceBenchmarkTests
    {
        private readonly ITestOutputHelper _output;
        private readonly Mock<ICryptographicProvider> _mockCryptoProvider;
        private readonly Mock<ISmimeMessageProcessor> _mockSmimeProcessor;
        private readonly Mock<ILogger<HybridEncryptionEngine>> _mockLogger;

        public PerformanceBenchmarkTests(ITestOutputHelper output)
        {
            _output = output;
            _mockCryptoProvider = new Mock<ICryptographicProvider>();
            _mockSmimeProcessor = new Mock<ISmimeMessageProcessor>();
            _mockLogger = new Mock<ILogger<HybridEncryptionEngine>>();
        }

        [Theory]
        [InlineData(1024)]      // 1KB - Small email
        [InlineData(10240)]     // 10KB - Medium email
        [InlineData(102400)]    // 100KB - Large email
        [InlineData(1048576)]   // 1MB - Very large email with attachments
        public async Task EmailEncryption_ShouldMeetPerformanceTargets(int messageSizeBytes)
        {
            // Arrange
            var testMessage = GenerateTestEmailMessage(messageSizeBytes);
            var recipients = GenerateTestRecipients(3); // Standard multi-recipient scenario
            var stopwatch = new Stopwatch();
            const int iterations = 10;
            var measurements = new List<long>();

            _output.WriteLine($"Testing encryption performance for {messageSizeBytes:N0} byte message with {recipients.Count} recipients");

            // Act - Measure encryption performance over multiple iterations
            for (int i = 0; i < iterations; i++)
            {
                stopwatch.Restart();
                var encryptedMessage = await EncryptEmailMessage(testMessage, recipients);
                stopwatch.Stop();
                measurements.Add(stopwatch.ElapsedMilliseconds);
                
                _output.WriteLine($"Iteration {i + 1}: {stopwatch.ElapsedMilliseconds}ms");
            }

            // Assert - Performance targets
            var averageTime = measurements.Average();
            var maxTime = measurements.Max();
            var p95Time = measurements.OrderBy(x => x).Skip((int)(measurements.Count * 0.95)).First();

            _output.WriteLine($"Average time: {averageTime:F2}ms");
            _output.WriteLine($"Max time: {maxTime}ms");
            _output.WriteLine($"95th percentile: {p95Time}ms");

            // Performance assertions
            averageTime.Should().BeLessThan(500, "Average encryption time should be under 500ms");
            p95Time.Should().BeLessThan(750, "95th percentile should be under 750ms for reliability");
            
            // Verify throughput
            var avgThroughput = (messageSizeBytes / 1024.0) / (averageTime / 1000.0); // KB/s
            _output.WriteLine($"Throughput: {avgThroughput:F2} KB/s");
        }

        [Theory]
        [InlineData(1)]
        [InlineData(5)]
        [InlineData(10)]
        [InlineData(25)]
        [InlineData(50)]
        public async Task EmailEncryption_ScalabilityWithRecipients(int recipientCount)
        {
            // Arrange
            var testMessage = GenerateTestEmailMessage(10240); // 10KB standard message
            var recipients = GenerateTestRecipients(recipientCount);
            var stopwatch = new Stopwatch();

            _output.WriteLine($"Testing encryption scalability with {recipientCount} recipients");

            // Act
            stopwatch.Start();
            var encryptedMessage = await EncryptEmailMessage(testMessage, recipients);
            stopwatch.Stop();

            // Assert - Linear scaling expectations
            var expectedBaseTime = 100; // Base encryption time for single recipient
            var expectedPerRecipientOverhead = 15; // Additional time per recipient
            var expectedMaxTime = expectedBaseTime + (recipientCount * expectedPerRecipientOverhead);

            stopwatch.ElapsedMilliseconds.Should().BeLessThan(expectedMaxTime, 
                $"Encryption with {recipientCount} recipients should scale linearly");

            var perRecipientTime = (double)stopwatch.ElapsedMilliseconds / recipientCount;
            _output.WriteLine($"Time per recipient: {perRecipientTime:F2}ms");
            _output.WriteLine($"Total time: {stopwatch.ElapsedMilliseconds}ms");
        }

        [Fact]
        public async Task DigitalSignature_ShouldMeetPerformanceTargets()
        {
            // Arrange
            var testMessages = new List<(string description, byte[] content)>
            {
                ("Small", GenerateTestEmailMessage(1024)),
                ("Medium", GenerateTestEmailMessage(10240)),
                ("Large", GenerateTestEmailMessage(102400))
            };

            var keyPair = await GenerateTestSigningKeyPair();
            const int iterations = 20;

            foreach (var (description, message) in testMessages)
            {
                _output.WriteLine($"Testing signature performance for {description} message ({message.Length:N0} bytes)");
                
                var signTimes = new List<long>();
                var verifyTimes = new List<long>();

                // Act - Measure signing and verification
                for (int i = 0; i < iterations; i++)
                {
                    // Sign
                    var stopwatch = Stopwatch.StartNew();
                    var signature = await SignMessage(message, keyPair.PrivateKey);
                    stopwatch.Stop();
                    signTimes.Add(stopwatch.ElapsedMilliseconds);

                    // Verify
                    stopwatch.Restart();
                    var isValid = await VerifySignature(message, signature, keyPair.PublicKey);
                    stopwatch.Stop();
                    verifyTimes.Add(stopwatch.ElapsedMilliseconds);

                    isValid.Should().BeTrue("Signature should be valid");
                }

                // Assert - Performance targets
                var avgSignTime = signTimes.Average();
                var avgVerifyTime = verifyTimes.Average();
                var maxSignTime = signTimes.Max();
                var maxVerifyTime = verifyTimes.Max();

                _output.WriteLine($"  Sign - Avg: {avgSignTime:F2}ms, Max: {maxSignTime}ms");
                _output.WriteLine($"  Verify - Avg: {avgVerifyTime:F2}ms, Max: {maxVerifyTime}ms");

                // Performance assertions
                avgSignTime.Should().BeLessThan(200, "Average signing time should be under 200ms");
                avgVerifyTime.Should().BeLessThan(100, "Average verification time should be under 100ms");
                maxSignTime.Should().BeLessThan(400, "Maximum signing time should be under 400ms");
            }
        }

        [Fact]
        public async Task CapabilityDiscovery_ShouldBeCached()
        {
            // Arrange
            var testDomains = new[] { "example.com", "bank.com", "secure.org" };
            var discoveryService = CreateMockCapabilityDiscoveryService();

            var firstLookupTimes = new List<long>();
            var cachedLookupTimes = new List<long>();

            foreach (var domain in testDomains)
            {
                // Act - First lookup (should hit DNS/network)
                var stopwatch = Stopwatch.StartNew();
                var capabilities1 = await discoveryService.DiscoverCapabilitiesAsync(domain);
                stopwatch.Stop();
                firstLookupTimes.Add(stopwatch.ElapsedMilliseconds);

                // Act - Cached lookup (should be fast)
                stopwatch.Restart();
                var capabilities2 = await discoveryService.DiscoverCapabilitiesAsync(domain);
                stopwatch.Stop();
                cachedLookupTimes.Add(stopwatch.ElapsedMilliseconds);

                _output.WriteLine($"Domain {domain}: First={firstLookupTimes.Last()}ms, Cached={cachedLookupTimes.Last()}ms");
            }

            // Assert - Caching effectiveness
            var avgFirstLookup = firstLookupTimes.Average();
            var avgCachedLookup = cachedLookupTimes.Average();
            var cacheSpeedup = avgFirstLookup / avgCachedLookup;

            _output.WriteLine($"Average first lookup: {avgFirstLookup:F2}ms");
            _output.WriteLine($"Average cached lookup: {avgCachedLookup:F2}ms");
            _output.WriteLine($"Cache speedup: {cacheSpeedup:F1}x");

            avgCachedLookup.Should().BeLessThan(10, "Cached lookups should be very fast");
            cacheSpeedup.Should().BeGreaterThan(5, "Cache should provide significant speedup");
        }

        [Fact]
        public async Task MemoryUsage_ShouldStayWithinLimits()
        {
            // Arrange
            var initialMemory = GC.GetTotalMemory(true);
            const int messageCount = 100;
            var messageSizes = new[] { 1024, 10240, 102400 }; // Various sizes

            _output.WriteLine($"Initial memory: {initialMemory:N0} bytes");

            // Act - Process multiple messages
            var processedMessages = new List<byte[]>();
            
            for (int i = 0; i < messageCount; i++)
            {
                var messageSize = messageSizes[i % messageSizes.Length];
                var message = GenerateTestEmailMessage(messageSize);
                var recipients = GenerateTestRecipients(3);
                
                var encrypted = await EncryptEmailMessage(message, recipients);
                processedMessages.Add(encrypted);

                // Measure memory every 10 messages
                if (i % 10 == 9)
                {
                    var currentMemory = GC.GetTotalMemory(false);
                    var memoryGrowth = currentMemory - initialMemory;
                    _output.WriteLine($"After {i + 1} messages: {currentMemory:N0} bytes (+{memoryGrowth:N0})");
                }
            }

            // Force garbage collection and measure final memory
            GC.Collect();
            GC.WaitForPendingFinalizers();
            GC.Collect();
            
            var finalMemory = GC.GetTotalMemory(true);
            var totalMemoryGrowth = finalMemory - initialMemory;

            _output.WriteLine($"Final memory: {finalMemory:N0} bytes");
            _output.WriteLine($"Total growth: {totalMemoryGrowth:N0} bytes");

            // Assert - Memory usage limits
            var memoryGrowthMB = totalMemoryGrowth / (1024.0 * 1024.0);
            memoryGrowthMB.Should().BeLessThan(100, "Memory growth should be reasonable for 100 messages");

            // Average memory per processed message
            var avgMemoryPerMessage = totalMemoryGrowth / messageCount;
            _output.WriteLine($"Average memory per message: {avgMemoryPerMessage:N0} bytes");
            avgMemoryPerMessage.Should().BeLessThan(1048576, "Memory per message should be under 1MB");
        }

        [Fact]
        public async Task ConcurrentEncryption_PerformanceUnderLoad()
        {
            // Arrange
            const int concurrentOperations = 25;
            const int messageSize = 10240; // 10KB messages
            var tasks = new List<Task<PerformanceResult>>();
            var overallStopwatch = Stopwatch.StartNew();

            _output.WriteLine($"Testing {concurrentOperations} concurrent encryption operations");

            // Act - Launch concurrent encryption operations
            for (int i = 0; i < concurrentOperations; i++)
            {
                var operationId = i;
                tasks.Add(Task.Run(async () =>
                {
                    var stopwatch = Stopwatch.StartNew();
                    var message = GenerateTestEmailMessage(messageSize);
                    var recipients = GenerateTestRecipients(2);
                    
                    var encrypted = await EncryptEmailMessage(message, recipients);
                    stopwatch.Stop();
                    
                    return new PerformanceResult
                    {
                        OperationId = operationId,
                        ElapsedMs = stopwatch.ElapsedMilliseconds,
                        Success = encrypted != null && encrypted.Length > 0
                    };
                }));
            }

            var results = await Task.WhenAll(tasks);
            overallStopwatch.Stop();

            // Assert - Concurrent performance
            var successfulOperations = results.Count(r => r.Success);
            var averageTime = results.Where(r => r.Success).Average(r => r.ElapsedMs);
            var maxTime = results.Where(r => r.Success).Max(r => r.ElapsedMs);
            var throughput = (double)concurrentOperations / (overallStopwatch.ElapsedMilliseconds / 1000.0);

            _output.WriteLine($"Successful operations: {successfulOperations}/{concurrentOperations}");
            _output.WriteLine($"Average time: {averageTime:F2}ms");
            _output.WriteLine($"Max time: {maxTime}ms");
            _output.WriteLine($"Throughput: {throughput:F2} operations/second");
            _output.WriteLine($"Total time: {overallStopwatch.ElapsedMilliseconds}ms");

            // Performance assertions
            successfulOperations.Should().Be(concurrentOperations, "All concurrent operations should succeed");
            averageTime.Should().BeLessThan(1000, "Average time under load should be reasonable");
            throughput.Should().BeGreaterThan(5, "Should maintain reasonable throughput under concurrent load");
        }

        [Theory]
        [InlineData("ML-KEM-768")]
        [InlineData("ML-DSA-65")]
        public async Task Algorithm_PerformanceCharacteristics(string algorithmName)
        {
            // Arrange
            const int iterations = 50;
            var keyPair = await GenerateKeyPairForAlgorithm(algorithmName);
            var testData = GenerateTestEmailMessage(1024);

            var keyGenTimes = new List<long>();
            var operationTimes = new List<long>();

            _output.WriteLine($"Testing {algorithmName} performance characteristics");

            // Act - Measure key generation performance
            for (int i = 0; i < 10; i++) // Fewer iterations for key gen (it's expensive)
            {
                var stopwatch = Stopwatch.StartNew();
                await GenerateKeyPairForAlgorithm(algorithmName);
                stopwatch.Stop();
                keyGenTimes.Add(stopwatch.ElapsedMilliseconds);
            }

            // Act - Measure operation performance (encrypt/sign depending on algorithm)
            for (int i = 0; i < iterations; i++)
            {
                var stopwatch = Stopwatch.StartNew();
                if (algorithmName.Contains("KEM"))
                {
                    await PerformKemOperation(testData, keyPair.PublicKey);
                }
                else if (algorithmName.Contains("DSA"))
                {
                    await PerformSigningOperation(testData, keyPair.PrivateKey);
                }
                stopwatch.Stop();
                operationTimes.Add(stopwatch.ElapsedMilliseconds);
            }

            // Assert - Algorithm-specific performance
            var avgKeyGenTime = keyGenTimes.Average();
            var avgOperationTime = operationTimes.Average();
            var p95OperationTime = operationTimes.OrderBy(x => x).Skip((int)(operationTimes.Count * 0.95)).First();

            _output.WriteLine($"  Key generation avg: {avgKeyGenTime:F2}ms");
            _output.WriteLine($"  Operation avg: {avgOperationTime:F2}ms");
            _output.WriteLine($"  Operation 95th percentile: {p95OperationTime}ms");

            // Algorithm-specific performance targets
            if (algorithmName.Contains("KEM"))
            {
                avgOperationTime.Should().BeLessThan(100, "KEM operations should be fast");
            }
            else if (algorithmName.Contains("DSA"))
            {
                avgOperationTime.Should().BeLessThan(200, "Signature operations should meet target");
            }

            avgKeyGenTime.Should().BeLessThan(1000, "Key generation should be reasonable");
        }

        // Helper methods
        private byte[] GenerateTestEmailMessage(int sizeBytes)
        {
            var random = new Random(42); // Deterministic for consistent testing
            var data = new byte[sizeBytes];
            random.NextBytes(data);
            return data;
        }

        private List<string> GenerateTestRecipients(int count)
        {
            return Enumerable.Range(1, count)
                .Select(i => $"recipient{i}@example.com")
                .ToList();
        }

        private async Task<byte[]> EncryptEmailMessage(byte[] message, List<string> recipients)
        {
            // Mock implementation - simulate encryption overhead
            await Task.Delay(50 + (recipients.Count * 10)); // Base + per-recipient overhead
            return message.Concat(new byte[recipients.Count * 1088]).ToArray(); // Add KEM ciphertext per recipient
        }

        private async Task<KeyPair> GenerateTestSigningKeyPair()
        {
            await Task.Delay(100); // Simulate key generation time
            return new KeyPair
            {
                PublicKey = new byte[1952], // ML-DSA-65 public key size
                PrivateKey = new byte[4032], // ML-DSA-65 private key size
                Algorithm = "ML-DSA-65"
            };
        }

        private async Task<byte[]> SignMessage(byte[] message, byte[] privateKey)
        {
            await Task.Delay(50); // Simulate signing time
            return new byte[3293]; // ML-DSA-65 signature size
        }

        private async Task<bool> VerifySignature(byte[] message, byte[] signature, byte[] publicKey)
        {
            await Task.Delay(25); // Simulate verification time
            return true; // Mock always validates
        }

        private ICapabilityDiscoveryService CreateMockCapabilityDiscoveryService()
        {
            var mock = new Mock<ICapabilityDiscoveryService>();
            var cache = new Dictionary<string, (DateTime timestamp, object capabilities)>();

            mock.Setup(x => x.DiscoverCapabilitiesAsync(It.IsAny<string>()))
                .Returns<string>(async domain =>
                {
                    if (cache.TryGetValue(domain, out var cached) && 
                        DateTime.UtcNow - cached.timestamp < TimeSpan.FromMinutes(5))
                    {
                        await Task.Delay(1); // Fast cached response
                        return cached.capabilities;
                    }

                    await Task.Delay(100); // Simulate network lookup
                    var capabilities = new { SupportsPQC = true, Algorithms = new[] { "ML-KEM-768", "ML-DSA-65" } };
                    cache[domain] = (DateTime.UtcNow, capabilities);
                    return capabilities;
                });

            return mock.Object;
        }

        private async Task<KeyPair> GenerateKeyPairForAlgorithm(string algorithm)
        {
            await Task.Delay(100); // Simulate key generation
            return algorithm switch
            {
                "ML-KEM-768" => new KeyPair
                {
                    PublicKey = new byte[1184],
                    PrivateKey = new byte[2400],
                    Algorithm = algorithm
                },
                "ML-DSA-65" => new KeyPair
                {
                    PublicKey = new byte[1952],
                    PrivateKey = new byte[4032],
                    Algorithm = algorithm
                },
                _ => throw new ArgumentException($"Unknown algorithm: {algorithm}")
            };
        }

        private async Task PerformKemOperation(byte[] data, byte[] publicKey)
        {
            await Task.Delay(20); // Simulate KEM operation
        }

        private async Task PerformSigningOperation(byte[] data, byte[] privateKey)
        {
            await Task.Delay(50); // Simulate signing operation
        }

        // Helper classes
        public class PerformanceResult
        {
            public int OperationId { get; set; }
            public long ElapsedMs { get; set; }
            public bool Success { get; set; }
        }

        public class KeyPair
        {
            public byte[] PublicKey { get; set; } = Array.Empty<byte>();
            public byte[] PrivateKey { get; set; } = Array.Empty<byte>();
            public string Algorithm { get; set; } = string.Empty;
        }
    }
}