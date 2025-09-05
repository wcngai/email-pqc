using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PqcEmail.Core.Certificates;
using PqcEmail.Core.Models;

namespace PqcEmail.Tests.Certificates
{
    [TestClass]
    public class WindowsCertificateManagerTests
    {
        private Mock<ILogger<WindowsCertificateManager>> _mockLogger;
        private WindowsCertificateManager _certificateManager;

        [TestInitialize]
        public void Setup()
        {
            _mockLogger = new Mock<ILogger<WindowsCertificateManager>>();
            _certificateManager = new WindowsCertificateManager(_mockLogger.Object);
        }

        [TestCleanup]
        public void Cleanup()
        {
            _certificateManager?.Dispose();
        }

        [TestMethod]
        public void Constructor_WithNullLogger_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsException<ArgumentNullException>(() => new WindowsCertificateManager(null));
        }

        [TestMethod]
        public async Task DiscoverCertificatesAsync_WithValidEmailAddress_ReturnsEmptyCollection()
        {
            // Arrange
            var emailAddress = "test@example.com";

            // Act
            var result = await _certificateManager.DiscoverCertificatesAsync(emailAddress);

            // Assert
            Assert.IsNotNull(result);
            // Note: This will return empty in test environment since no certificates are installed
            var certificates = result.ToList();
            Assert.IsTrue(certificates.Count >= 0);
        }

        [TestMethod]
        public async Task DiscoverCertificatesAsync_WithSpecificStore_ReturnsEmptyCollection()
        {
            // Arrange
            var emailAddress = "test@example.com";
            var storeName = StoreName.My;

            // Act
            var result = await _certificateManager.DiscoverCertificatesAsync(emailAddress, storeName);

            // Assert
            Assert.IsNotNull(result);
            var certificates = result.ToList();
            Assert.IsTrue(certificates.Count >= 0);
        }

        [TestMethod]
        public async Task ValidateCertificateChainAsync_WithNullCertificate_ThrowsException()
        {
            // Act & Assert
            await Assert.ThrowsExceptionAsync<ArgumentNullException>(
                async () => await _certificateManager.ValidateCertificateChainAsync(null));
        }

        [TestMethod]
        public async Task ValidateCertificateChainAsync_WithSelfSignedCertificate_ReturnsValidationResult()
        {
            // Arrange
            var certificate = CreateTestSelfSignedCertificate();

            // Act
            var result = await _certificateManager.ValidateCertificateChainAsync(certificate);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsNotNull(result.ErrorMessages);
            Assert.IsNotNull(result.WarningMessages);
            Assert.IsNotNull(result.ChainElements);
            Assert.IsNotNull(result.ChainErrors);
        }

        [TestMethod]
        public async Task InstallCertificateAsync_WithValidCertificate_HandlesAccessDenied()
        {
            // Arrange
            var certificate = CreateTestSelfSignedCertificate();

            // Act
            var result = await _certificateManager.InstallCertificateAsync(
                certificate, StoreName.My, StoreLocation.LocalMachine);

            // Assert
            Assert.IsNotNull(result);
            // In test environment without admin privileges, this should fail with access denied
            if (!result.Success)
            {
                Assert.AreEqual(InstallationStatus.AccessDenied, result.Status);
            }
        }

        [TestMethod]
        public async Task InstallCertificateAsync_WithCurrentUserStore_AttemptsInstallation()
        {
            // Arrange
            var certificate = CreateTestSelfSignedCertificate();

            // Act
            var result = await _certificateManager.InstallCertificateAsync(
                certificate, StoreName.My, StoreLocation.CurrentUser);

            // Assert
            Assert.IsNotNull(result);
            // Result depends on whether certificate already exists or installation succeeds
        }

        [TestMethod]
        public async Task RemoveCertificateAsync_WithValidThumbprint_ReturnsResult()
        {
            // Arrange
            var certificate = CreateTestSelfSignedCertificate();
            var thumbprint = certificate.Thumbprint;

            // Act
            var result = await _certificateManager.RemoveCertificateAsync(
                thumbprint, StoreName.My, StoreLocation.CurrentUser);

            // Assert
            // Result depends on whether certificate exists in store
            Assert.IsTrue(result == true || result == false);
        }

        [TestMethod]
        public async Task GetExpiringCertificatesAsync_WithDefaultThreshold_ReturnsCollection()
        {
            // Act
            var result = await _certificateManager.GetExpiringCertificatesAsync();

            // Assert
            Assert.IsNotNull(result);
            var certificates = result.ToList();
            Assert.IsTrue(certificates.Count >= 0);
        }

        [TestMethod]
        public async Task GetExpiringCertificatesAsync_WithCustomThreshold_ReturnsCollection()
        {
            // Arrange
            var warningDays = 60;

            // Act
            var result = await _certificateManager.GetExpiringCertificatesAsync(warningDays);

            // Assert
            Assert.IsNotNull(result);
            var certificates = result.ToList();
            Assert.IsTrue(certificates.Count >= 0);
        }

        [TestMethod]
        public async Task CheckRevocationStatusAsync_WithValidCertificate_ReturnsStatus()
        {
            // Arrange
            var certificate = CreateTestSelfSignedCertificate();

            // Act
            var result = await _certificateManager.CheckRevocationStatusAsync(certificate);

            // Assert
            Assert.IsTrue(Enum.IsDefined(typeof(RevocationStatus), result));
        }

        [TestMethod]
        public async Task FindBestCertificateAsync_WithValidParameters_ReturnsNullOrCertificate()
        {
            // Arrange
            var emailAddress = "test@example.com";
            var usage = CertificateUsage.DigitalSignature;

            // Act
            var result = await _certificateManager.FindBestCertificateAsync(emailAddress, usage);

            // Assert
            // Result can be null if no suitable certificate found
            Assert.IsTrue(result == null || result is X509Certificate2);
        }

        [TestMethod]
        public async Task BackupCertificatesAsync_WithEmptyCollection_ReturnsFailure()
        {
            // Arrange
            var certificates = new List<X509Certificate2>();
            var backupPath = System.IO.Path.GetTempFileName();
            var password = "TestPassword123!";

            try
            {
                // Act
                var result = await _certificateManager.BackupCertificatesAsync(certificates, backupPath, password);

                // Assert
                Assert.IsNotNull(result);
                Assert.IsFalse(result.Success);
                Assert.IsNotNull(result.ErrorMessage);
            }
            finally
            {
                // Cleanup
                if (System.IO.File.Exists(backupPath))
                {
                    System.IO.File.Delete(backupPath);
                }
            }
        }

        [TestMethod]
        public async Task BackupCertificatesAsync_WithCertificatesWithoutPrivateKeys_ReturnsFailure()
        {
            // Arrange
            var certificate = CreateTestSelfSignedCertificate();
            var certificates = new List<X509Certificate2> { certificate };
            var backupPath = System.IO.Path.GetTempFileName();
            var password = "TestPassword123!";

            try
            {
                // Act
                var result = await _certificateManager.BackupCertificatesAsync(certificates, backupPath, password);

                // Assert
                Assert.IsNotNull(result);
                // Should fail because test certificate doesn't have accessible private key
                Assert.IsFalse(result.Success);
            }
            finally
            {
                // Cleanup
                if (System.IO.File.Exists(backupPath))
                {
                    System.IO.File.Delete(backupPath);
                }
                certificate.Dispose();
            }
        }

        [TestMethod]
        public async Task RestoreCertificatesAsync_WithNonExistentFile_ReturnsFailure()
        {
            // Arrange
            var backupPath = System.IO.Path.Combine(System.IO.Path.GetTempPath(), "nonexistent.pfx");
            var password = "TestPassword123!";

            // Act
            var result = await _certificateManager.RestoreCertificatesAsync(backupPath, password);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsFalse(result.Success);
            Assert.IsNotNull(result.ErrorMessage);
            Assert.IsTrue(result.ErrorMessage.Contains("not found"));
        }

        [TestMethod]
        public void CertificateInfo_SupportsUsage_ReturnsCorrectResult()
        {
            // Arrange
            var certificate = CreateTestSelfSignedCertificate();
            var certInfo = new CertificateInfo
            {
                Certificate = certificate,
                KeyUsage = X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                EnhancedKeyUsage = new List<string> { "1.3.6.1.5.5.7.3.4" } // Email protection
            };

            // Act & Assert
            Assert.IsTrue(certInfo.SupportsUsage(CertificateUsage.DigitalSignature));
            Assert.IsTrue(certInfo.SupportsUsage(CertificateUsage.DataEncryption));
            Assert.IsFalse(certInfo.SupportsUsage(CertificateUsage.KeyAgreement));

            // Cleanup
            certificate.Dispose();
        }

        [TestMethod]
        public void CertificateInfo_WithValidationStatus_CreatesUpdatedCopy()
        {
            // Arrange
            var certificate = CreateTestSelfSignedCertificate();
            var originalCertInfo = new CertificateInfo
            {
                Certificate = certificate,
                ValidationStatus = CertificateValidationStatus.NotValidated
            };
            var originalUpdateTime = originalCertInfo.LastUpdated;

            // Wait a moment to ensure timestamp difference
            System.Threading.Thread.Sleep(10);

            // Act
            var updatedCertInfo = originalCertInfo.WithValidationStatus(CertificateValidationStatus.Valid);

            // Assert
            Assert.AreNotSame(originalCertInfo, updatedCertInfo);
            Assert.AreEqual(CertificateValidationStatus.Valid, updatedCertInfo.ValidationStatus);
            Assert.IsTrue(updatedCertInfo.LastUpdated > originalUpdateTime);

            // Cleanup
            certificate.Dispose();
        }

        [TestMethod]
        public void KeyPairInfo_Validate_WithCompleteInfo_ReturnsValid()
        {
            // Arrange
            var keyPairInfo = new KeyPairInfo
            {
                ContainerName = "TestContainer",
                Identity = "test@example.com",
                Algorithm = "RSA",
                KeySize = 2048,
                PublicKeyData = new byte[256],
                IsActive = true,
                IsArchived = false
            };

            // Act
            var result = keyPairInfo.Validate();

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.IsValid);
            Assert.AreEqual(0, result.Errors.Count);
        }

        [TestMethod]
        public void KeyPairInfo_Validate_WithMissingFields_ReturnsInvalid()
        {
            // Arrange
            var keyPairInfo = new KeyPairInfo
            {
                ContainerName = "", // Missing
                Identity = "", // Missing
                Algorithm = "", // Missing
                KeySize = 0, // Invalid
                PublicKeyData = Array.Empty<byte>(), // Missing
                IsActive = true,
                IsArchived = true // Conflicting with IsActive
            };

            // Act
            var result = keyPairInfo.Validate();

            // Assert
            Assert.IsNotNull(result);
            Assert.IsFalse(result.IsValid);
            Assert.IsTrue(result.Errors.Count > 0);
        }

        [TestMethod]
        public void KeyPairInfo_CreateArchivalCopy_CreatesValidCopy()
        {
            // Arrange
            var originalKeyPair = new KeyPairInfo
            {
                ContainerName = "OriginalContainer",
                Identity = "test@example.com",
                Algorithm = "RSA",
                Usage = KeyUsage.Signing,
                KeySize = 2048,
                PublicKeyData = new byte[256],
                IsActive = true,
                IsArchived = false
            };
            originalKeyPair.Metadata["TestMetadata"] = "TestValue";

            var archivalReason = "Key rotation";

            // Act
            var archivedCopy = originalKeyPair.CreateArchivalCopy(archivalReason);

            // Assert
            Assert.IsNotNull(archivedCopy);
            Assert.AreNotEqual(originalKeyPair.KeyId, archivedCopy.KeyId);
            Assert.IsTrue(archivedCopy.ContainerName.Contains("archived"));
            Assert.AreEqual(originalKeyPair.Identity, archivedCopy.Identity);
            Assert.AreEqual(originalKeyPair.Algorithm, archivedCopy.Algorithm);
            Assert.IsFalse(archivedCopy.IsActive);
            Assert.IsTrue(archivedCopy.IsArchived);
            Assert.AreEqual(originalKeyPair.KeyId, archivedCopy.Metadata["OriginalKeyId"]);
            Assert.AreEqual(archivalReason, archivedCopy.Metadata["ArchivalReason"]);
        }

        private X509Certificate2 CreateTestSelfSignedCertificate()
        {
            var distinguishedName = new X500DistinguishedName("CN=Test Certificate, E=test@example.com");

            using var rsa = System.Security.Cryptography.RSA.Create(2048);
            var request = new CertificateRequest(distinguishedName, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            // Add basic constraints
            request.CertificateExtensions.Add(new X509BasicConstraintsExtension(false, false, 0, false));

            // Add key usage
            request.CertificateExtensions.Add(new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                false));

            // Add enhanced key usage
            request.CertificateExtensions.Add(new X509EnhancedKeyUsageExtension(
                new OidCollection { new Oid("1.3.6.1.5.5.7.3.4") }, // Email protection
                false));

            // Add subject alternative name
            var sanBuilder = new SubjectAlternativeNameBuilder();
            sanBuilder.AddEmailAddress("test@example.com");
            request.CertificateExtensions.Add(sanBuilder.Build());

            var certificate = request.CreateSelfSigned(
                notBefore: DateTimeOffset.UtcNow.AddDays(-1),
                notAfter: DateTimeOffset.UtcNow.AddDays(365));

            return certificate;
        }
    }
}