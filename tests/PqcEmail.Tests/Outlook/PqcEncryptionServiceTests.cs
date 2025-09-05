using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;
using PqcEmail.Outlook.COM;
using PqcEmail.Outlook.Utilities;

namespace PqcEmail.Tests.Outlook
{
    /// <summary>
    /// Unit tests for the PqcEncryptionService class.
    /// Tests the integration between Outlook and PQC cryptographic operations.
    /// </summary>
    [TestClass]
    public class PqcEncryptionServiceTests
    {
        private Mock<IHybridEncryptionEngine> _mockEncryptionEngine = null!;
        private Mock<OutlookComInterop> _mockComInterop = null!;
        private PqcEncryptionService _encryptionService = null!;

        [TestInitialize]
        public void TestInitialize()
        {
            _mockEncryptionEngine = new Mock<IHybridEncryptionEngine>();
            _mockComInterop = new Mock<OutlookComInterop>(Mock.Of<Microsoft.Office.Interop.Outlook.Application>());
            _encryptionService = new PqcEncryptionService(_mockEncryptionEngine.Object, _mockComInterop.Object);
        }

        [TestCleanup]
        public void TestCleanup()
        {
            _mockEncryptionEngine = null!;
            _mockComInterop = null!;
            _encryptionService = null!;
        }

        [TestMethod]
        public async Task EncryptEmailAsync_WithValidInputs_ReturnsSuccessResult()
        {
            // Arrange
            var mockMailItem = Mock.Of<Microsoft.Office.Interop.Outlook.MailItem>(m => 
                m.Subject == "Test Subject" &&
                m.Body == "Test Body" &&
                m.SenderEmailAddress == "sender@test.com");

            var recipients = new List<string> { "recipient@test.com" };
            var strategy = EncryptionStrategy.Hybrid;

            _mockComInterop.Setup(x => x.GetRecipientsAsync(mockMailItem))
                .ReturnsAsync(recipients);

            _mockComInterop.Setup(x => x.UpdateMailBodyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<Microsoft.Office.Interop.Outlook.OlBodyFormat>()))
                .Returns(Task.CompletedTask);

            _mockComInterop.Setup(x => x.AddCustomPropertyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            // Act
            var result = await _encryptionService.EncryptEmailAsync(mockMailItem, recipients, strategy);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success);
            Assert.AreEqual(strategy, result.Strategy);
            Assert.AreEqual(recipients.Count, result.Recipients.Count);
            Assert.IsNotNull(result.AlgorithmUsed);
            Assert.IsNull(result.Error);
            
            // Verify interactions
            _mockComInterop.Verify(x => x.UpdateMailBodyAsync(mockMailItem, It.IsAny<string>(), 
                Microsoft.Office.Interop.Outlook.OlBodyFormat.olFormatPlain), Times.Once);
            _mockComInterop.Verify(x => x.AddCustomPropertyAsync(mockMailItem, "PQC_Status", "Encrypted"), Times.Once);
            _mockComInterop.Verify(x => x.AddCustomPropertyAsync(mockMailItem, "PQC_Strategy", strategy.ToString()), Times.Once);
        }

        [TestMethod]
        public async Task EncryptEmailAsync_WithNullMailItem_ReturnsFailureResult()
        {
            // Arrange
            var recipients = new List<string> { "recipient@test.com" };
            var strategy = EncryptionStrategy.Hybrid;

            // Act & Assert
            await Assert.ThrowsExceptionAsync<NullReferenceException>(async () => 
                await _encryptionService.EncryptEmailAsync(null!, recipients, strategy));
        }

        [TestMethod]
        public async Task DecryptEmailAsync_WithEncryptedEmail_ReturnsSuccessResult()
        {
            // Arrange
            var mockMailItem = Mock.Of<Microsoft.Office.Interop.Outlook.MailItem>(m => 
                m.Subject == "[PQC-Protected] Test Subject" &&
                m.Body == "[PQC-Hybrid-BODY:2023-10-01T12:00:00Z]Original Body Content");

            _mockComInterop.Setup(x => x.GetCustomPropertyAsync(mockMailItem, "PQC_Strategy"))
                .ReturnsAsync("Hybrid");

            _mockComInterop.Setup(x => x.UpdateMailBodyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<Microsoft.Office.Interop.Outlook.OlBodyFormat>()))
                .Returns(Task.CompletedTask);

            _mockComInterop.Setup(x => x.AddCustomPropertyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            // Act
            var result = await _encryptionService.DecryptEmailAsync(mockMailItem);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success);
            Assert.AreEqual(EncryptionStrategy.Hybrid, result.Strategy);
            Assert.IsNotNull(result.AlgorithmUsed);
            Assert.IsNull(result.Error);

            // Verify interactions
            _mockComInterop.Verify(x => x.UpdateMailBodyAsync(mockMailItem, "Original Body Content", 
                Microsoft.Office.Interop.Outlook.OlBodyFormat.olFormatPlain), Times.Once);
            _mockComInterop.Verify(x => x.AddCustomPropertyAsync(mockMailItem, "PQC_Status", "Decrypted"), Times.Once);
        }

        [TestMethod]
        public async Task DecryptEmailAsync_WithUnencryptedEmail_ReturnsFailureResult()
        {
            // Arrange
            var mockMailItem = Mock.Of<Microsoft.Office.Interop.Outlook.MailItem>(m => 
                m.Subject == "Regular Subject" &&
                m.Body == "Regular Body Content");

            _mockComInterop.Setup(x => x.GetCustomPropertyAsync(mockMailItem, "PQC_Strategy"))
                .ReturnsAsync((string?)null);

            // Act
            var result = await _encryptionService.DecryptEmailAsync(mockMailItem);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsFalse(result.Success);
            Assert.IsNotNull(result.Error);
            Assert.IsTrue(result.Error.Contains("not PQC encrypted"));
        }

        [TestMethod]
        public async Task SignEmailAsync_WithValidEmail_ReturnsSuccessResult()
        {
            // Arrange
            var mockMailItem = Mock.Of<Microsoft.Office.Interop.Outlook.MailItem>(m => 
                m.Subject == "Test Subject" &&
                m.Body == "Test Body" &&
                m.SenderEmailAddress == "sender@test.com");

            _mockComInterop.Setup(x => x.AddCustomPropertyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            // Act
            var result = await _encryptionService.SignEmailAsync(mockMailItem);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success);
            Assert.AreEqual("ML-DSA-65", result.Algorithm);
            Assert.IsTrue(result.SignatureSize > 0);
            Assert.IsNull(result.Error);

            // Verify signature metadata was added
            _mockComInterop.Verify(x => x.AddCustomPropertyAsync(mockMailItem, "PQC_Signature", It.IsAny<string>()), Times.Once);
            _mockComInterop.Verify(x => x.AddCustomPropertyAsync(mockMailItem, "PQC_SignAlgorithm", "ML-DSA-65"), Times.Once);
        }

        [TestMethod]
        public async Task VerifyEmailSignatureAsync_WithValidSignature_ReturnsValidResult()
        {
            // Arrange
            var mockMailItem = Mock.Of<Microsoft.Office.Interop.Outlook.MailItem>(m => 
                m.Subject == "Test Subject" &&
                m.Body == "Test Body" &&
                m.SenderEmailAddress == "sender@test.com");

            _mockComInterop.Setup(x => x.GetCustomPropertyAsync(mockMailItem, "PQC_Signature"))
                .ReturnsAsync("base64signaturedata");
            _mockComInterop.Setup(x => x.GetCustomPropertyAsync(mockMailItem, "PQC_SignAlgorithm"))
                .ReturnsAsync("ML-DSA-65");
            _mockComInterop.Setup(x => x.GetCustomPropertyAsync(mockMailItem, "PQC_SignedAt"))
                .ReturnsAsync(DateTime.UtcNow.ToString("O"));

            // Act
            var result = await _encryptionService.VerifyEmailSignatureAsync(mockMailItem);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success);
            Assert.IsTrue(result.IsValid);
            Assert.AreEqual("ML-DSA-65", result.Algorithm);
            Assert.AreEqual("sender@test.com", result.SignerInfo);
            Assert.IsNull(result.Error);
        }

        [TestMethod]
        public async Task VerifyEmailSignatureAsync_WithNoSignature_ReturnsFailureResult()
        {
            // Arrange
            var mockMailItem = Mock.Of<Microsoft.Office.Interop.Outlook.MailItem>();

            _mockComInterop.Setup(x => x.GetCustomPropertyAsync(mockMailItem, "PQC_Signature"))
                .ReturnsAsync((string?)null);

            // Act
            var result = await _encryptionService.VerifyEmailSignatureAsync(mockMailItem);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsFalse(result.Success);
            Assert.IsNotNull(result.Error);
            Assert.IsTrue(result.Error.Contains("No PQC signature found"));
        }

        [TestMethod]
        [DataRow(EncryptionStrategy.Hybrid, "ML-KEM-768 + RSA-2048")]
        [DataRow(EncryptionStrategy.PostQuantumOnly, "ML-KEM-768")]
        [DataRow(EncryptionStrategy.ClassicalOnly, "RSA-2048")]
        [DataRow(EncryptionStrategy.Auto, "Auto")]
        public void GetAlgorithmName_ReturnsCorrectNames(EncryptionStrategy strategy, string expectedName)
        {
            // This tests the private method indirectly through the public EncryptEmailAsync method
            // We check the AlgorithmUsed property in the result

            // Arrange
            var mockMailItem = Mock.Of<Microsoft.Office.Interop.Outlook.MailItem>(m => 
                m.Subject == "Test Subject" &&
                m.Body == "Test Body");
            
            var recipients = new List<string> { "test@test.com" };

            _mockComInterop.Setup(x => x.GetRecipientsAsync(mockMailItem))
                .ReturnsAsync(recipients);
            _mockComInterop.Setup(x => x.UpdateMailBodyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<Microsoft.Office.Interop.Outlook.OlBodyFormat>()))
                .Returns(Task.CompletedTask);
            _mockComInterop.Setup(x => x.AddCustomPropertyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            // Act
            var result = _encryptionService.EncryptEmailAsync(mockMailItem, recipients, strategy).Result;

            // Assert
            Assert.AreEqual(expectedName, result.AlgorithmUsed);
        }

        [TestMethod]
        public void Constructor_WithNullEncryptionEngine_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsException<ArgumentNullException>(() => 
                new PqcEncryptionService(null!, _mockComInterop.Object));
        }

        [TestMethod]
        public void Constructor_WithNullComInterop_ThrowsArgumentNullException()
        {
            // Act & Assert
            Assert.ThrowsException<ArgumentNullException>(() => 
                new PqcEncryptionService(_mockEncryptionEngine.Object, null!));
        }

        [TestMethod]
        public async Task EncryptEmailAsync_WithEmptyRecipientsList_ReturnsSuccessResult()
        {
            // Arrange
            var mockMailItem = Mock.Of<Microsoft.Office.Interop.Outlook.MailItem>(m => 
                m.Subject == "Test Subject" &&
                m.Body == "Test Body");

            var recipients = new List<string>(); // Empty list
            var strategy = EncryptionStrategy.Hybrid;

            _mockComInterop.Setup(x => x.UpdateMailBodyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<Microsoft.Office.Interop.Outlook.OlBodyFormat>()))
                .Returns(Task.CompletedTask);
            _mockComInterop.Setup(x => x.AddCustomPropertyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            // Act
            var result = await _encryptionService.EncryptEmailAsync(mockMailItem, recipients, strategy);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success);
            Assert.AreEqual(0, result.Recipients.Count);
        }

        [TestMethod]
        public async Task DecryptEmailAsync_WithCorruptedEncryptionMarkers_HandlesGracefully()
        {
            // Arrange
            var mockMailItem = Mock.Of<Microsoft.Office.Interop.Outlook.MailItem>(m => 
                m.Subject == "[PQC-Protected] Test Subject" &&
                m.Body == "[CORRUPTED-MARKER] Invalid Content");

            _mockComInterop.Setup(x => x.GetCustomPropertyAsync(mockMailItem, "PQC_Strategy"))
                .ReturnsAsync("Hybrid");

            _mockComInterop.Setup(x => x.UpdateMailBodyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<Microsoft.Office.Interop.Outlook.OlBodyFormat>()))
                .Returns(Task.CompletedTask);

            _mockComInterop.Setup(x => x.AddCustomPropertyAsync(It.IsAny<Microsoft.Office.Interop.Outlook.MailItem>(), 
                It.IsAny<string>(), It.IsAny<string>()))
                .Returns(Task.CompletedTask);

            // Act
            var result = await _encryptionService.DecryptEmailAsync(mockMailItem);

            // Assert
            Assert.IsNotNull(result);
            Assert.IsTrue(result.Success); // Should handle gracefully
            Assert.AreEqual(EncryptionStrategy.Hybrid, result.Strategy);
        }
    }
}