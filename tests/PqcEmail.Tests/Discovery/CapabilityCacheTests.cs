using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using NUnit.Framework;
using PqcEmail.Core.Discovery;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Discovery
{
    [TestFixture]
    public class CapabilityCacheTests
    {
        private CapabilityCache _cache;

        [SetUp]
        public void Setup()
        {
            _cache = new CapabilityCache();
        }

        [TearDown]
        public void TearDown()
        {
            _cache?.Dispose();
        }

        [Test]
        public async Task GetAsync_WithNonExistentKey_ReturnsNull()
        {
            // Arrange
            const string email = "nonexistent@example.com";

            // Act
            var result = await _cache.GetAsync(email);

            // Assert
            Assert.That(result, Is.Null);
        }

        [Test]
        public async Task SetAsync_AndGetAsync_StoresAndRetrievesCapabilities()
        {
            // Arrange
            const string email = "test@example.com";
            var capabilities = CreateTestCapabilities(email);
            var ttl = TimeSpan.FromMinutes(30);

            // Act
            await _cache.SetAsync(email, capabilities, ttl);
            var retrieved = await _cache.GetAsync(email);

            // Assert
            Assert.That(retrieved, Is.Not.Null);
            Assert.That(retrieved.EmailAddress, Is.EqualTo(email));
            Assert.That(retrieved.Source, Is.EqualTo(CapabilitySource.Cache));
        }

        [Test]
        public async Task GetAsync_WithExpiredEntry_ReturnsNull()
        {
            // Arrange
            const string email = "expired@example.com";
            var capabilities = CreateTestCapabilities(email);
            var shortTtl = TimeSpan.FromMilliseconds(1);

            // Act
            await _cache.SetAsync(email, capabilities, shortTtl);
            await Task.Delay(TimeSpan.FromMilliseconds(10)); // Wait for expiry
            var retrieved = await _cache.GetAsync(email);

            // Assert
            Assert.That(retrieved, Is.Null);
        }

        [Test]
        public async Task SetAsync_WithSameKey_UpdatesEntry()
        {
            // Arrange
            const string email = "update@example.com";
            var originalCapabilities = CreateTestCapabilities(email);
            var updatedCapabilities = CreateTestCapabilities(email);
            updatedCapabilities.ConfidenceLevel = 0.9;
            var ttl = TimeSpan.FromMinutes(30);

            // Act
            await _cache.SetAsync(email, originalCapabilities, ttl);
            await _cache.SetAsync(email, updatedCapabilities, ttl);
            var retrieved = await _cache.GetAsync(email);

            // Assert
            Assert.That(retrieved, Is.Not.Null);
            Assert.That(retrieved.ConfidenceLevel, Is.EqualTo(0.9));
        }

        [Test]
        public async Task RemoveAsync_RemovesEntry()
        {
            // Arrange
            const string email = "remove@example.com";
            var capabilities = CreateTestCapabilities(email);
            var ttl = TimeSpan.FromMinutes(30);

            // Act
            await _cache.SetAsync(email, capabilities, ttl);
            await _cache.RemoveAsync(email);
            var retrieved = await _cache.GetAsync(email);

            // Assert
            Assert.That(retrieved, Is.Null);
        }

        [Test]
        public async Task ClearAsync_RemovesAllEntries()
        {
            // Arrange
            var emails = new[] { "user1@example.com", "user2@example.com", "user3@example.com" };
            var ttl = TimeSpan.FromMinutes(30);

            foreach (var email in emails)
            {
                var capabilities = CreateTestCapabilities(email);
                await _cache.SetAsync(email, capabilities, ttl);
            }

            // Act
            await _cache.ClearAsync();

            // Assert
            foreach (var email in emails)
            {
                var retrieved = await _cache.GetAsync(email);
                Assert.That(retrieved, Is.Null);
            }
        }

        [Test]
        public async Task GetStatsAsync_ReturnsAccurateStatistics()
        {
            // Arrange
            const string email1 = "stats1@example.com";
            const string email2 = "stats2@example.com";
            const string nonExistent = "nonexistent@example.com";
            var capabilities = CreateTestCapabilities(email1);
            var ttl = TimeSpan.FromMinutes(30);

            // Act - Set some entries
            await _cache.SetAsync(email1, capabilities, ttl);
            await _cache.SetAsync(email2, CreateTestCapabilities(email2), ttl);

            // Perform some gets (hits and misses)
            await _cache.GetAsync(email1); // Hit
            await _cache.GetAsync(email2); // Hit
            await _cache.GetAsync(nonExistent); // Miss

            var stats = await _cache.GetStatsAsync();

            // Assert
            Assert.That(stats.TotalEntries, Is.EqualTo(2));
            Assert.That(stats.Hits, Is.EqualTo(2));
            Assert.That(stats.Misses, Is.EqualTo(1));
            Assert.That(stats.HitRate, Is.EqualTo(2.0 / 3.0).Within(0.001));
            Assert.That(stats.MemoryUsage, Is.GreaterThan(0));
        }

        [Test]
        public async Task Cache_WithCaseInsensitiveEmails_TreatsAsSameKey()
        {
            // Arrange
            const string emailLower = "case@example.com";
            const string emailUpper = "CASE@EXAMPLE.COM";
            const string emailMixed = "Case@Example.Com";
            var capabilities = CreateTestCapabilities(emailLower);
            var ttl = TimeSpan.FromMinutes(30);

            // Act
            await _cache.SetAsync(emailLower, capabilities, ttl);
            var retrievedUpper = await _cache.GetAsync(emailUpper);
            var retrievedMixed = await _cache.GetAsync(emailMixed);

            // Assert
            Assert.That(retrievedUpper, Is.Not.Null);
            Assert.That(retrievedMixed, Is.Not.Null);
            Assert.That(retrievedUpper.EmailAddress, Is.EqualTo(emailLower));
            Assert.That(retrievedMixed.EmailAddress, Is.EqualTo(emailLower));
        }

        [Test]
        public void SetAsync_WithNullEmailAddress_ThrowsArgumentException()
        {
            // Arrange
            var capabilities = CreateTestCapabilities("test@example.com");
            var ttl = TimeSpan.FromMinutes(30);

            // Act & Assert
            Assert.ThrowsAsync<ArgumentException>(() => _cache.SetAsync(null!, capabilities, ttl));
        }

        [Test]
        public void SetAsync_WithEmptyEmailAddress_ThrowsArgumentException()
        {
            // Arrange
            var capabilities = CreateTestCapabilities("test@example.com");
            var ttl = TimeSpan.FromMinutes(30);

            // Act & Assert
            Assert.ThrowsAsync<ArgumentException>(() => _cache.SetAsync("", capabilities, ttl));
        }

        [Test]
        public void SetAsync_WithNullCapabilities_ThrowsArgumentNullException()
        {
            // Arrange
            const string email = "test@example.com";
            var ttl = TimeSpan.FromMinutes(30);

            // Act & Assert
            Assert.ThrowsAsync<ArgumentNullException>(() => _cache.SetAsync(email, null!, ttl));
        }

        [Test]
        public void SetAsync_WithZeroTtl_ThrowsArgumentException()
        {
            // Arrange
            const string email = "test@example.com";
            var capabilities = CreateTestCapabilities(email);
            var ttl = TimeSpan.Zero;

            // Act & Assert
            Assert.ThrowsAsync<ArgumentException>(() => _cache.SetAsync(email, capabilities, ttl));
        }

        [Test]
        public void SetAsync_WithNegativeTtl_ThrowsArgumentException()
        {
            // Arrange
            const string email = "test@example.com";
            var capabilities = CreateTestCapabilities(email);
            var ttl = TimeSpan.FromMinutes(-1);

            // Act & Assert
            Assert.ThrowsAsync<ArgumentException>(() => _cache.SetAsync(email, capabilities, ttl));
        }

        [Test]
        public void GetAsync_WithNullEmailAddress_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentException>(() => _cache.GetAsync(null!));
        }

        [Test]
        public void GetAsync_WithEmptyEmailAddress_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentException>(() => _cache.GetAsync(""));
        }

        [Test]
        public async Task Cache_WithManyEntries_MaintainsPerformance()
        {
            // Arrange
            const int entryCount = 1000;
            var ttl = TimeSpan.FromMinutes(30);

            // Act - Add many entries
            for (int i = 0; i < entryCount; i++)
            {
                var email = $"user{i}@example.com";
                var capabilities = CreateTestCapabilities(email);
                await _cache.SetAsync(email, capabilities, ttl);
            }

            // Verify some entries
            var retrieved = await _cache.GetAsync("user500@example.com");
            var stats = await _cache.GetStatsAsync();

            // Assert
            Assert.That(retrieved, Is.Not.Null);
            Assert.That(retrieved.EmailAddress, Is.EqualTo("user500@example.com"));
            Assert.That(stats.TotalEntries, Is.EqualTo(entryCount));
        }

        private RecipientCapabilities CreateTestCapabilities(string email)
        {
            return new RecipientCapabilities
            {
                EmailAddress = email,
                Source = CapabilitySource.SmimeaDns,
                DiscoveredAt = DateTimeOffset.UtcNow,
                ExpiresAt = DateTimeOffset.UtcNow.AddHours(24),
                ConfidenceLevel = 0.8,
                SupportedModes = new List<CryptographicMode> { CryptographicMode.Hybrid },
                SupportedKemAlgorithms = new List<string> { "ML-KEM-768" },
                SupportedSignatureAlgorithms = new List<string> { "ML-DSA-65" },
                SupportedClassicalAlgorithms = new List<string> { "RSA-OAEP-2048" },
                Metadata = new Dictionary<string, object>
                {
                    ["test"] = "value",
                    ["created_in_test"] = true
                }
            };
        }
    }
}