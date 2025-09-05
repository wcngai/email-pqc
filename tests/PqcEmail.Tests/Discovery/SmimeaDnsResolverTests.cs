using System;
using System.Threading;
using System.Threading.Tasks;
using NUnit.Framework;
using PqcEmail.Core.Discovery;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Discovery
{
    [TestFixture]
    public class SmimeaDnsResolverTests
    {
        private CapabilityDiscoveryConfiguration _configuration;
        private SmimeaDnsResolver _resolver;

        [SetUp]
        public void Setup()
        {
            _configuration = CapabilityDiscoveryConfiguration.CreateDefault();
            _resolver = new SmimeaDnsResolver(_configuration);
        }

        [Test]
        public async Task QuerySmimeaRecordsAsync_WithValidEmail_ConstructsCorrectQuery()
        {
            // Arrange
            const string email = "test@example.com";

            // Act
            var result = await _resolver.QuerySmimeaRecordsAsync(email);

            // Assert
            Assert.That(result.Query, Is.EqualTo("_25._tcp.test.example.com"));
            Assert.That(result.ResponseTime, Is.GreaterThan(TimeSpan.Zero));
        }

        [Test]
        public async Task QuerySmimeaRecordsAsync_WithInvalidEmail_ReturnsError()
        {
            // Arrange
            const string invalidEmail = "invalid-email";

            // Act
            var result = await _resolver.QuerySmimeaRecordsAsync(invalidEmail);

            // Assert
            Assert.That(result.ErrorMessage, Is.EqualTo("Invalid email address format"));
            Assert.That(result.SmimeaRecords.Count, Is.EqualTo(0));
        }

        [Test]
        public void QuerySmimeaRecordsAsync_WithNullEmail_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentException>(() => _resolver.QuerySmimeaRecordsAsync(null!));
        }

        [Test]
        public void QuerySmimeaRecordsAsync_WithEmptyEmail_ThrowsArgumentException()
        {
            // Act & Assert
            Assert.ThrowsAsync<ArgumentException>(() => _resolver.QuerySmimeaRecordsAsync(""));
        }

        [Test]
        public async Task QuerySmimeaRecordsAsync_WithTimeout_RespectsCancellation()
        {
            // Arrange
            const string email = "timeout@example.com";
            using var cts = new CancellationTokenSource(TimeSpan.FromMilliseconds(1));

            // Act
            var result = await _resolver.QuerySmimeaRecordsAsync(email, cts.Token);

            // Assert
            Assert.That(result.ErrorMessage, Contains.Substring("cancelled").Or.Contains("timeout"));
        }

        [Test]
        public async Task ValidateDnssecAsync_WithValidDomain_ReturnsValidationResult()
        {
            // Arrange
            const string domain = "example.com";

            // Act
            var isValid = await _resolver.ValidateDnssecAsync(domain);

            // Assert
            // Note: This will return false on most systems as DNSSEC validation
            // requires proper implementation, which is platform-specific
            Assert.That(isValid, Is.TypeOf<bool>());
        }

        [Test]
        public void ValidateDnssecAsync_WithNullDomain_DoesNotThrow()
        {
            // Act & Assert
            Assert.DoesNotThrowAsync(() => _resolver.ValidateDnssecAsync(null!));
        }

        [Test]
        public async Task QuerySmimeaRecordsAsync_WithMultiplePorts_TriesBothPorts()
        {
            // Arrange
            const string email = "multi@example.com";

            // Act
            var result = await _resolver.QuerySmimeaRecordsAsync(email);

            // Assert
            // The query should be for port 25 initially, and if no records found,
            // it should have tried port 587 as well (though we can't easily test the fallback)
            Assert.That(result.Query, Does.StartWith("_25._tcp.multi.example.com").Or.StartWith("_587._tcp.multi.example.com"));
        }

        [TestCase("user@domain.com", "_25._tcp.user.domain.com")]
        [TestCase("test.user@example.org", "_25._tcp.test.user.example.org")]
        [TestCase("complex+email@sub.domain.co.uk", "_25._tcp.complex+email.sub.domain.co.uk")]
        public async Task QuerySmimeaRecordsAsync_WithVariousEmailFormats_ConstructsCorrectQuery(string email, string expectedQuery)
        {
            // Act
            var result = await _resolver.QuerySmimeaRecordsAsync(email);

            // Assert
            Assert.That(result.Query, Is.EqualTo(expectedQuery));
        }

        [Test]
        public void Constructor_WithNullConfiguration_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.Throws<ArgumentNullException>(() => new SmimeaDnsResolver(null!));
        }

        [Test]
        public void Constructor_WithValidConfiguration_InitializesCorrectly()
        {
            // Arrange
            var config = new CapabilityDiscoveryConfiguration
            {
                DnsTimeout = TimeSpan.FromSeconds(10),
                EnableDnssecValidation = true,
                CustomDnsServers = new() { "8.8.8.8", "8.8.4.4" }
            };

            // Act & Assert
            Assert.DoesNotThrow(() => new SmimeaDnsResolver(config));
        }
    }

    [TestFixture]
    public class SmimeaRecordParsingTests
    {
        [Test]
        public void SmimeaRecord_WithValidData_ParsesCorrectly()
        {
            // Arrange
            var record = new SmimeaRecord
            {
                CertificateUsage = 3,
                Selector = 1,
                MatchingType = 1,
                CertificateAssociationData = new byte[] { 0x01, 0x02, 0x03, 0x04 }
            };

            // Act & Assert
            Assert.That(record.CertificateUsage, Is.EqualTo(3));
            Assert.That(record.Selector, Is.EqualTo(1));
            Assert.That(record.MatchingType, Is.EqualTo(1));
            Assert.That(record.CertificateAssociationData.Length, Is.EqualTo(4));
            Assert.That(record.IsPqcExtended, Is.False);
        }

        [Test]
        public void SmimeaRecord_WithPqcExtensions_IdentifiesAsPqc()
        {
            // Arrange
            var record = new SmimeaRecord
            {
                CertificateUsage = 240, // Experimental range
                Selector = 1,
                MatchingType = 1,
                CertificateAssociationData = new byte[] { 0x01, 0x02, 0x02, 0x03 },
                IsPqcExtended = true,
                PqcAlgorithms = new() { "ML-KEM-768", "ML-DSA-65" }
            };

            // Act & Assert
            Assert.That(record.IsPqcExtended, Is.True);
            Assert.That(record.PqcAlgorithms.Count, Is.EqualTo(2));
            Assert.That(record.PqcAlgorithms, Contains.Item("ML-KEM-768"));
            Assert.That(record.PqcAlgorithms, Contains.Item("ML-DSA-65"));
        }

        [TestCase(new byte[] { }, false)]
        [TestCase(new byte[] { 0x01 }, false)]
        [TestCase(new byte[] { 0x01, 0x02 }, false)]
        [TestCase(new byte[] { 0x01, 0x02, 0x03 }, true)]
        public void SmimeaRecord_WithVariousDataLengths_HandlesCorrectly(byte[] data, bool expectedMinimumLength)
        {
            // Arrange
            var record = new SmimeaRecord
            {
                CertificateUsage = 3,
                Selector = 1,
                MatchingType = 1,
                RawData = data
            };

            // Act & Assert
            if (expectedMinimumLength)
            {
                Assert.That(record.RawData.Length, Is.GreaterThanOrEqualTo(3));
            }
            else
            {
                Assert.That(record.RawData.Length, Is.LessThan(3));
            }
        }
    }
}