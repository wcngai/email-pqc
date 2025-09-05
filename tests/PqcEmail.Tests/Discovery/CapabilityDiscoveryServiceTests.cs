using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using Moq;
using PqcEmail.Core.Discovery;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Discovery
{
    [TestFixture]
    public class CapabilityDiscoveryServiceTests
    {
        private Mock<ISmimeaDnsResolver> _mockDnsResolver;
        private Mock<ICapabilityCache> _mockCache;
        private Mock<IRecipientCapabilityRepository> _mockRepository;
        private Mock<IActiveDirectoryCapabilityProvider> _mockAdProvider;
        private CapabilityDiscoveryConfiguration _configuration;
        private CapabilityDiscoveryService _service;

        [SetUp]
        public void Setup()
        {
            _mockDnsResolver = new Mock<ISmimeaDnsResolver>();
            _mockCache = new Mock<ICapabilityCache>();
            _mockRepository = new Mock<IRecipientCapabilityRepository>();
            _mockAdProvider = new Mock<IActiveDirectoryCapabilityProvider>();
            
            _configuration = CapabilityDiscoveryConfiguration.CreateDefault();
            
            _service = new CapabilityDiscoveryService(
                _configuration,
                _mockDnsResolver.Object,
                _mockCache.Object,
                _mockRepository.Object,
                _mockAdProvider.Object);
        }

        [TearDown]
        public void TearDown()
        {
            _service?.Dispose();
        }

        [Test]
        public async Task DiscoverCapabilitiesAsync_WithCachedData_ReturnsCachedResult()
        {
            // Arrange
            const string email = "test@example.com";
            var cachedCapabilities = CreateTestCapabilities(email, CapabilitySource.Cache);
            
            _mockCache.Setup(x => x.GetAsync(email, It.IsAny<CancellationToken>()))
                     .ReturnsAsync(cachedCapabilities);

            // Act
            var result = await _service.DiscoverCapabilitiesAsync(email);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.FromCache, Is.True);
            Assert.That(result.Capabilities, Is.EqualTo(cachedCapabilities));
            Assert.That(result.DiscoveryTime, Is.LessThan(TimeSpan.FromSeconds(1)));

            // Verify cache was checked but DNS wasn't called
            _mockCache.Verify(x => x.GetAsync(email, It.IsAny<CancellationToken>()), Times.Once);
            _mockDnsResolver.Verify(x => x.QuerySmimeaRecordsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Test]
        public async Task DiscoverCapabilitiesAsync_WithInternalRecipient_ReturnsActiveDirectoryResult()
        {
            // Arrange
            const string email = "internal@company.com";
            var adCapabilities = CreateTestCapabilities(email, CapabilitySource.ActiveDirectory);
            
            _mockCache.Setup(x => x.GetAsync(email, It.IsAny<CancellationToken>()))
                     .ReturnsAsync((RecipientCapabilities?)null);
            
            _mockAdProvider.Setup(x => x.IsInternalRecipientAsync(email, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(true);
            
            _mockAdProvider.Setup(x => x.QueryCapabilitiesAsync(email, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(adCapabilities);

            // Act
            var result = await _service.DiscoverCapabilitiesAsync(email);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.FromCache, Is.False);
            Assert.That(result.Capabilities.Source, Is.EqualTo(CapabilitySource.ActiveDirectory));
            Assert.That(result.Capabilities.EmailAddress, Is.EqualTo(email));

            // Verify AD was queried but DNS wasn't
            _mockAdProvider.Verify(x => x.QueryCapabilitiesAsync(email, It.IsAny<CancellationToken>()), Times.Once);
            _mockDnsResolver.Verify(x => x.QuerySmimeaRecordsAsync(It.IsAny<string>(), It.IsAny<CancellationToken>()), Times.Never);
        }

        [Test]
        public async Task DiscoverCapabilitiesAsync_WithExternalRecipient_UsesDnsResolver()
        {
            // Arrange
            const string email = "external@example.com";
            var dnsResult = CreateTestDnsResult(email);
            
            _mockCache.Setup(x => x.GetAsync(email, It.IsAny<CancellationToken>()))
                     .ReturnsAsync((RecipientCapabilities?)null);
            
            _mockAdProvider.Setup(x => x.IsInternalRecipientAsync(email, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(false);
            
            _mockDnsResolver.Setup(x => x.QuerySmimeaRecordsAsync(email, It.IsAny<CancellationToken>()))
                           .ReturnsAsync(dnsResult);

            // Act
            var result = await _service.DiscoverCapabilitiesAsync(email);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.FromCache, Is.False);
            Assert.That(result.Capabilities.Source, Is.EqualTo(CapabilitySource.SmimeaDns));
            Assert.That(result.Capabilities.EmailAddress, Is.EqualTo(email));

            // Verify DNS was queried
            _mockDnsResolver.Verify(x => x.QuerySmimeaRecordsAsync(email, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Test]
        public async Task DiscoverCapabilitiesAsync_WithNoSourcesAvailable_UsesFallback()
        {
            // Arrange
            const string email = "unknown@example.com";
            
            _mockCache.Setup(x => x.GetAsync(email, It.IsAny<CancellationToken>()))
                     .ReturnsAsync((RecipientCapabilities?)null);
            
            _mockAdProvider.Setup(x => x.IsInternalRecipientAsync(email, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(false);
            
            _mockDnsResolver.Setup(x => x.QuerySmimeaRecordsAsync(email, It.IsAny<CancellationToken>()))
                           .ReturnsAsync(new DnsQueryResult { Query = email, ErrorMessage = "No records found" });

            _mockRepository.Setup(x => x.GetCapabilitiesAsync(email, It.IsAny<CancellationToken>()))
                          .ReturnsAsync((RecipientCapabilities?)null);

            // Act
            var result = await _service.DiscoverCapabilitiesAsync(email);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Capabilities.Source, Is.EqualTo(CapabilitySource.Fallback));
            Assert.That(result.Capabilities.EmailAddress, Is.EqualTo(email));
            Assert.That(result.Capabilities.SupportedModes.Count, Is.GreaterThan(0));
        }

        [Test]
        public async Task DiscoverCapabilitiesAsync_WithPqcSmimeaRecords_ExtractsPqcCapabilities()
        {
            // Arrange
            const string email = "pqc@example.com";
            var dnsResult = CreateTestDnsResultWithPqc(email);
            
            _mockCache.Setup(x => x.GetAsync(email, It.IsAny<CancellationToken>()))
                     .ReturnsAsync((RecipientCapabilities?)null);
            
            _mockAdProvider.Setup(x => x.IsInternalRecipientAsync(email, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(false);
            
            _mockDnsResolver.Setup(x => x.QuerySmimeaRecordsAsync(email, It.IsAny<CancellationToken>()))
                           .ReturnsAsync(dnsResult);

            // Act
            var result = await _service.DiscoverCapabilitiesAsync(email);

            // Assert
            Assert.That(result.IsSuccess, Is.True);
            Assert.That(result.Capabilities.SupportsPqcOnly, Is.True);
            Assert.That(result.Capabilities.SupportsHybrid, Is.True);
            Assert.That(result.Capabilities.SupportedKemAlgorithms, Contains.Item("ML-KEM-768"));
            Assert.That(result.Capabilities.SupportedSignatureAlgorithms, Contains.Item("ML-DSA-65"));
        }

        [Test]
        public async Task DiscoverCapabilitiesAsync_MultipleRecipients_ProcessesInParallel()
        {
            // Arrange
            var emails = new[] { "user1@example.com", "user2@example.com", "user3@example.com" };
            
            foreach (var email in emails)
            {
                _mockCache.Setup(x => x.GetAsync(email, It.IsAny<CancellationToken>()))
                         .ReturnsAsync((RecipientCapabilities?)null);
                
                _mockAdProvider.Setup(x => x.IsInternalRecipientAsync(email, It.IsAny<CancellationToken>()))
                              .ReturnsAsync(false);
                
                _mockDnsResolver.Setup(x => x.QuerySmimeaRecordsAsync(email, It.IsAny<CancellationToken>()))
                               .ReturnsAsync(CreateTestDnsResult(email));
            }

            // Act
            var results = await _service.DiscoverCapabilitiesAsync(emails);

            // Assert
            Assert.That(results.Count, Is.EqualTo(3));
            Assert.That(results.Values.All(r => r.IsSuccess), Is.True);
            
            // Verify all emails were processed
            foreach (var email in emails)
            {
                Assert.That(results.ContainsKey(email), Is.True);
                Assert.That(results[email].Capabilities.EmailAddress, Is.EqualTo(email));
            }
        }

        [Test]
        public async Task DiscoverCapabilitiesAsync_WithTimeout_ReturnsTimeoutError()
        {
            // Arrange
            const string email = "timeout@example.com";
            var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1));
            
            _mockCache.Setup(x => x.GetAsync(email, It.IsAny<CancellationToken>()))
                     .ReturnsAsync((RecipientCapabilities?)null);
            
            _mockAdProvider.Setup(x => x.IsInternalRecipientAsync(email, It.IsAny<CancellationToken>()))
                          .Returns(async (string e, CancellationToken ct) =>
                          {
                              await Task.Delay(TimeSpan.FromSeconds(1), ct);
                              return false;
                          });

            // Act
            var result = await _service.DiscoverCapabilitiesAsync(email, cts.Token);

            // Assert
            Assert.That(result.IsSuccess, Is.False);
            Assert.That(result.Error?.Type, Is.EqualTo(CapabilityErrorType.DnsTimeout));
        }

        [Test]
        public async Task SetCapabilitiesAsync_ManualCapabilities_StoresAndCaches()
        {
            // Arrange
            const string email = "manual@example.com";
            var capabilities = CreateTestCapabilities(email, CapabilitySource.Manual);

            // Act
            await _service.SetCapabilitiesAsync(email, capabilities);

            // Assert
            _mockCache.Verify(x => x.SetAsync(email, It.Is<RecipientCapabilities>(c => 
                c.EmailAddress == email && c.Source == CapabilitySource.Manual), 
                It.IsAny<TimeSpan>(), It.IsAny<CancellationToken>()), Times.Once);
            
            _mockRepository.Verify(x => x.StoreCapabilitiesAsync(It.Is<RecipientCapabilities>(c => 
                c.EmailAddress == email && c.Source == CapabilitySource.Manual), 
                It.IsAny<CancellationToken>()), Times.Once);
        }

        [Test]
        public async Task ClearCacheAsync_RemovesFromCacheAndRepository()
        {
            // Arrange
            const string email = "clear@example.com";

            // Act
            await _service.ClearCacheAsync(email);

            // Assert
            _mockCache.Verify(x => x.RemoveAsync(email, It.IsAny<CancellationToken>()), Times.Once);
            _mockRepository.Verify(x => x.DeleteCapabilitiesAsync(email, It.IsAny<CancellationToken>()), Times.Once);
        }

        [Test]
        public async Task GetStatsAsync_ReturnsAccumulatedStatistics()
        {
            // Arrange
            const string email = "stats@example.com";
            
            _mockCache.Setup(x => x.GetAsync(email, It.IsAny<CancellationToken>()))
                     .ReturnsAsync((RecipientCapabilities?)null);
            
            _mockAdProvider.Setup(x => x.IsInternalRecipientAsync(email, It.IsAny<CancellationToken>()))
                          .ReturnsAsync(false);
            
            _mockDnsResolver.Setup(x => x.QuerySmimeaRecordsAsync(email, It.IsAny<CancellationToken>()))
                           .ReturnsAsync(CreateTestDnsResult(email));

            // Act
            await _service.DiscoverCapabilitiesAsync(email);
            var stats = await _service.GetStatsAsync();

            // Assert
            Assert.That(stats.TotalQueries, Is.EqualTo(1));
            Assert.That(stats.SuccessfulQueries, Is.EqualTo(1));
            Assert.That(stats.CacheMisses, Is.EqualTo(1));
            Assert.That(stats.DnsQueries, Is.EqualTo(1));
            Assert.That(stats.AverageDiscoveryTime, Is.GreaterThan(TimeSpan.Zero));
        }

        [Test]
        public void DiscoverCapabilitiesAsync_WithInvalidEmail_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentException>(() => _service.DiscoverCapabilitiesAsync(""));
            Assert.ThrowsAsync<ArgumentException>(() => _service.DiscoverCapabilitiesAsync(null!));
        }

        private RecipientCapabilities CreateTestCapabilities(string email, CapabilitySource source)
        {
            return new RecipientCapabilities
            {
                EmailAddress = email,
                Source = source,
                DiscoveredAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
                ConfidenceLevel = 0.8,
                SupportedModes = new List<CryptographicMode> { CryptographicMode.Hybrid },
                SupportedKemAlgorithms = new List<string> { "ML-KEM-768" },
                SupportedSignatureAlgorithms = new List<string> { "ML-DSA-65" },
                SupportedClassicalAlgorithms = new List<string> { "RSA-OAEP-2048" }
            };
        }

        private DnsQueryResult CreateTestDnsResult(string email)
        {
            return new DnsQueryResult
            {
                Query = $"_25._tcp.{email.Split('@')[0]}.{email.Split('@')[1]}",
                ResponseTime = TimeSpan.FromMilliseconds(100),
                DnssecValidated = true,
                SmimeaRecords = new List<SmimeaRecord>
                {
                    new SmimeaRecord
                    {
                        CertificateUsage = 3,
                        Selector = 1,
                        MatchingType = 1,
                        CertificateAssociationData = new byte[] { 0x01, 0x02, 0x03, 0x04 }
                    }
                }
            };
        }

        private DnsQueryResult CreateTestDnsResultWithPqc(string email)
        {
            return new DnsQueryResult
            {
                Query = $"_25._tcp.{email.Split('@')[0]}.{email.Split('@')[1]}",
                ResponseTime = TimeSpan.FromMilliseconds(150),
                DnssecValidated = true,
                SmimeaRecords = new List<SmimeaRecord>
                {
                    new SmimeaRecord
                    {
                        CertificateUsage = 240, // Experimental PQC usage
                        Selector = 1,
                        MatchingType = 1,
                        CertificateAssociationData = new byte[] { 0x01, 0x02, 0x02, 0x03 },
                        IsPqcExtended = true,
                        PqcAlgorithms = new List<string> { "ML-KEM-768", "ML-DSA-65" }
                    }
                }
            };
        }
    }
}