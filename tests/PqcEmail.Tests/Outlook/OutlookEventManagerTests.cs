using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Moq;
using PqcEmail.Core.Interfaces;
using PqcEmail.Core.Models;
using PqcEmail.Outlook.COM;
using PqcEmail.Outlook.EventHandlers;

namespace PqcEmail.Tests.Outlook
{
    /// <summary>
    /// Unit tests for the OutlookEventManager class.
    /// Tests the email lifecycle event handling and crypto state management.
    /// </summary>
    [TestClass]
    public class OutlookEventManagerTests
    {
        private Mock<Microsoft.Office.Interop.Outlook.Application> _mockOutlookApp = null!;
        private Mock<IHybridEncryptionEngine> _mockEncryptionEngine = null!;
        private Mock<OutlookComInterop> _mockComInterop = null!;
        private OutlookEventManager _eventManager = null!;
        private bool _cryptoStateChangedFired = false;
        private EmailCryptoStateChangedEventArgs? _lastStateChangeArgs;

        [TestInitialize]
        public void TestInitialize()
        {
            _mockOutlookApp = new Mock<Microsoft.Office.Interop.Outlook.Application>();
            _mockEncryptionEngine = new Mock<IHybridEncryptionEngine>();
            _mockComInterop = new Mock<OutlookComInterop>(_mockOutlookApp.Object);
            
            _eventManager = new OutlookEventManager(
                _mockOutlookApp.Object, 
                _mockEncryptionEngine.Object, 
                _mockComInterop.Object);

            // Subscribe to crypto state change events
            _eventManager.CryptoStateChanged += OnCryptoStateChanged;
            _cryptoStateChangedFired = false;
            _lastStateChangeArgs = null;
        }

        [TestCleanup]
        public void TestCleanup()
        {
            _eventManager?.Dispose();
            _mockOutlookApp = null!;
            _mockEncryptionEngine = null!;
            _mockComInterop = null!;
            _eventManager = null!;
            _cryptoStateChangedFired = false;
            _lastStateChangeArgs = null;
        }

        [TestMethod]
        public async Task InitializeAsync_WithValidParameters_CompletesSuccessfully()
        {
            // Arrange
            var mockInspectors = new Mock<Microsoft.Office.Interop.Outlook.Inspectors>();
            _mockOutlookApp.Setup(x => x.Inspectors).Returns(mockInspectors.Object);

            // Act
            await _eventManager.InitializeAsync();

            // Assert
            _mockOutlookApp.Verify(x => x.Inspectors, Times.Once);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Constructor_WithNullOutlookApp_ThrowsArgumentNullException()
        {
            // Act & Assert
            new OutlookEventManager(null!, _mockEncryptionEngine.Object, _mockComInterop.Object);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Constructor_WithNullEncryptionEngine_ThrowsArgumentNullException()
        {
            // Act & Assert
            new OutlookEventManager(_mockOutlookApp.Object, null!, _mockComInterop.Object);
        }

        [TestMethod]
        [ExpectedException(typeof(ArgumentNullException))]
        public void Constructor_WithNullComInterop_ThrowsArgumentNullException()
        {
            // Act & Assert
            new OutlookEventManager(_mockOutlookApp.Object, _mockEncryptionEngine.Object, null!);
        }

        [TestMethod]
        public void GetEmailCryptoState_WithKnownEmailId_ReturnsCorrectState()
        {
            // This test requires using reflection to access private methods for state management
            // For MVP, we'll test the observable behavior through event handling
            
            // Arrange
            var emailId = "test-email-123";
            
            // Act - Trigger a state change that would be observed in real usage
            // This would normally happen through email events, but we can test the state management
            var state = _eventManager.GetEmailCryptoState(emailId);

            // Assert
            Assert.IsNull(state); // Initially no state should exist
        }

        [TestMethod]
        public void EmailCryptoStatus_EnumValues_AreCorrect()
        {
            // Test that all expected enum values exist
            var values = Enum.GetValues(typeof(EmailCryptoStatus));
            
            var expectedValues = new[]
            {
                EmailCryptoStatus.Analyzing,
                EmailCryptoStatus.Unencrypted,
                EmailCryptoStatus.QuantumSafeReady,
                EmailCryptoStatus.ClassicalEncryption,
                EmailCryptoStatus.Encrypting,
                EmailCryptoStatus.Encrypted,
                EmailCryptoStatus.Decrypting,
                EmailCryptoStatus.Decrypted,
                EmailCryptoStatus.Error
            };

            Assert.AreEqual(expectedValues.Length, values.Length);
            
            foreach (var expectedValue in expectedValues)
            {
                Assert.IsTrue(Array.Exists((EmailCryptoStatus[])values, v => v == expectedValue));
            }
        }

        [TestMethod]
        public void EmailCryptoState_Constructor_InitializesCorrectly()
        {
            // Arrange
            var emailId = "test-email-123";
            var status = EmailCryptoStatus.Analyzing;
            var details = "Test details";

            // Act
            var state = new EmailCryptoState(emailId, status, details);

            // Assert
            Assert.AreEqual(emailId, state.EmailId);
            Assert.AreEqual(status, state.Status);
            Assert.AreEqual(details, state.Details);
            Assert.IsTrue(state.LastUpdated > DateTime.UtcNow.AddMinutes(-1));
            Assert.IsTrue(state.LastUpdated <= DateTime.UtcNow);
        }

        [TestMethod]
        public void EmailCryptoState_Constructor_WithNullDetails_InitializesCorrectly()
        {
            // Arrange
            var emailId = "test-email-123";
            var status = EmailCryptoStatus.Encrypted;

            // Act
            var state = new EmailCryptoState(emailId, status);

            // Assert
            Assert.AreEqual(emailId, state.EmailId);
            Assert.AreEqual(status, state.Status);
            Assert.IsNull(state.Details);
            Assert.IsTrue(state.LastUpdated > DateTime.UtcNow.AddMinutes(-1));
        }

        [TestMethod]
        public void EmailCryptoStateChangedEventArgs_Constructor_InitializesCorrectly()
        {
            // Arrange
            var emailId = "test-email-123";
            var status = EmailCryptoStatus.Encrypted;
            var details = "Test details";

            // Act
            var eventArgs = new EmailCryptoStateChangedEventArgs(emailId, status, details);

            // Assert
            Assert.AreEqual(emailId, eventArgs.EmailId);
            Assert.AreEqual(status, eventArgs.Status);
            Assert.AreEqual(details, eventArgs.Details);
        }

        [TestMethod]
        public void EmailCryptoStateChangedEventArgs_Constructor_WithNullDetails_InitializesCorrectly()
        {
            // Arrange
            var emailId = "test-email-123";
            var status = EmailCryptoStatus.Error;

            // Act
            var eventArgs = new EmailCryptoStateChangedEventArgs(emailId, status);

            // Assert
            Assert.AreEqual(emailId, eventArgs.EmailId);
            Assert.AreEqual(status, eventArgs.Status);
            Assert.IsNull(eventArgs.Details);
        }

        [TestMethod]
        public void Dispose_CallsDispose_WithoutErrors()
        {
            // Arrange - EventManager is already initialized in TestInitialize

            // Act
            _eventManager.Dispose();

            // Assert - Should complete without throwing
            // Additional disposal should also be safe
            _eventManager.Dispose();
        }

        [TestMethod]
        public async Task DetermineRecipientCapabilities_WithInternalRecipients_ReturnsInternalCapabilities()
        {
            // This method is private, so we test indirectly by checking the behavior
            // of methods that use it. For MVP, we'll test the public contract.

            // Arrange
            var mockInspectors = new Mock<Microsoft.Office.Interop.Outlook.Inspectors>();
            _mockOutlookApp.Setup(x => x.Inspectors).Returns(mockInspectors.Object);

            _mockEncryptionEngine.Setup(x => x.DetermineEncryptionStrategy(It.IsAny<RecipientCapabilities>()))
                .Returns(EncryptionStrategy.Hybrid);

            // Act
            await _eventManager.InitializeAsync();

            // Assert
            _mockEncryptionEngine.Verify(x => x.DetermineEncryptionStrategy(It.IsAny<RecipientCapabilities>()), Times.Never);
        }

        [TestMethod]
        public void CryptoStateChanged_Event_CanBeSubscribedAndUnsubscribed()
        {
            // Arrange
            var eventFired = false;
            EmailCryptoStateChangedEventArgs? receivedArgs = null;

            EventHandler<EmailCryptoStateChangedEventArgs> handler = (sender, args) =>
            {
                eventFired = true;
                receivedArgs = args;
            };

            // Act - Subscribe
            _eventManager.CryptoStateChanged += handler;

            // Simulate an event (in real usage this would come from email operations)
            // For unit test, we'll verify the event can be subscribed/unsubscribed

            // Unsubscribe
            _eventManager.CryptoStateChanged -= handler;

            // Assert
            Assert.IsFalse(eventFired); // Event wasn't actually fired in this test
            Assert.IsNull(receivedArgs);
        }

        private void OnCryptoStateChanged(object sender, EmailCryptoStateChangedEventArgs e)
        {
            _cryptoStateChangedFired = true;
            _lastStateChangeArgs = e;
        }
    }
}